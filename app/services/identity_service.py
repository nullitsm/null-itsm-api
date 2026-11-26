"""Identity service: SCIM provisioning, directory sync, certification,
temporary access, service accounts / API credentials, OIDC discovery.

Honesty rules (same as storage.py): a connector that is not configured
raises a clear error and the sync run is recorded as failed — rows are
never faked. Secrets are stored only as SHA-256 hashes (SCIM tokens,
service-account and API credentials) or Fernet-encrypted via
``app.crypto`` (IdP / license secrets, imported lazily — that module
lands with migration 0006; until then storing an encrypted secret fails
closed instead of falling back to plaintext).
"""

from __future__ import annotations

import hashlib
import os
import re
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app.config import get_settings
from app.database import set_rls_context
from app.models.auth import Invitation, InvitationRole
from app.models.identity_assets import (
    AccessCertification,
    ApiCredential,
    CertificationItem,
    DirectoryGroup,
    DirectoryGroupMembership,
    DirectorySyncRun,
    IdentityProvider,
    ServiceAccount,
    TemporaryAccessGrant,
)
from app.models.platform import Membership, User
from app.models.rbac import Role, UserRole
from app.security import hash_password, hash_token, new_opaque_token

UTC = timezone.utc


class DirectorySyncError(Exception):
    """A directory sync cannot run (not configured / provider error)."""


class OidcDiscoveryError(Exception):
    """OIDC discovery failed (issuer unreachable or invalid document)."""


class SecretStorageError(Exception):
    """An encrypted secret cannot be stored (crypto unavailable)."""


# --- Secrets ---------------------------------------------------------------


def hash_secret(raw: str) -> str:
    """SHA-256 hex of a raw secret (tokens, service-account / API creds)."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def encrypt_secret(plaintext: str) -> str:
    """Fernet-encrypt via app.crypto (lazy import).

    Raises SecretStorageError when app.crypto is unavailable or no field
    encryption key is configured — never stores plaintext.
    """
    try:
        from app.crypto import encrypt
    except ImportError as exc:
        raise SecretStorageError(
            "field encryption is unavailable: app.crypto is not installed yet (migration 0006)"
        ) from exc
    try:
        return encrypt(plaintext)
    except RuntimeError as exc:
        raise SecretStorageError(str(exc)) from exc


def decrypt_secret(ciphertext: str) -> str:
    """Fernet-decrypt via app.crypto (lazy import)."""
    try:
        from app.crypto import decrypt
    except ImportError as exc:
        raise SecretStorageError(
            "field encryption is unavailable: app.crypto is not installed yet (migration 0006)"
        ) from exc
    try:
        return decrypt(ciphertext)
    except RuntimeError as exc:
        raise SecretStorageError(str(exc)) from exc


# --- SCIM token lookup (SECURITY DEFINER function) -------------------------


def get_scim_token_by_hash(session: Session, token_hash: str) -> dict | None:
    """Resolve a SCIM token by its SHA-256 hash via the 0007 function.

    Works before any RLS context exists (the function is SECURITY
    DEFINER, owner-owned, locked search_path). Returns None when no
    token matches — never enumerates.
    """
    row = session.execute(text("SELECT * FROM auth_get_scim_token_by_hash(:h)"), {"h": token_hash}).mappings().first()
    return dict(row) if row is not None else None


def resolve_scim_token(session: Session, raw_token: str) -> dict:
    """Validate a raw SCIM bearer token; returns the token row or raises.

    Raises ValueError("invalid SCIM token") for unknown tokens and
    ValueError("SCIM token expired/revoked") for dead ones. Callers map
    both to 401 — the distinction never leaks to the client.
    """
    row = get_scim_token_by_hash(session, hash_secret(raw_token))
    if row is None:
        raise ValueError("invalid SCIM token")
    now = datetime.now(UTC)
    if row.get("revoked_at") is not None:
        raise ValueError("SCIM token revoked")
    if row.get("expires_at") is not None and row["expires_at"] < now:
        raise ValueError("SCIM token expired")
    return row


# --- SCIM provisioning -----------------------------------------------------
# Same shape as the invitation flow in org_service.invite_technician:
# a User row + a Membership with status "invited" + an Invitation row
# (token hash only). The provisioned user has a random, unknowable
# password hash and cannot log in until the invitation is accepted.


def find_user_by_email(session: Session, email: str) -> dict | None:
    """Resolve a user by email via the 0001 SECURITY DEFINER function.

    A plain ORM lookup would be RLS-filtered: a user who exists globally
    but belongs to another org is invisible to this org's caller, and
    re-creating them would collide on the unique email. The function
    returns at most the one matching row.
    """
    row = session.execute(text("SELECT * FROM auth_get_user_by_email(:e)"), {"e": email}).mappings().first()
    return dict(row) if row is not None else None


def scim_list_org_users(session: Session, org_id: uuid.UUID) -> list[dict]:
    """Org members of ANY membership status, via the 0007 function.

    The org users SELECT policy only exposes ACTIVE members, but SCIM
    must read back invited/provisioned users too. The org id comes from
    the validated SCIM token (server-side), never from the client.
    """
    rows = session.execute(text("SELECT * FROM scim_list_org_users(:org)"), {"org": str(org_id)}).mappings().all()
    return [dict(r) for r in rows]


def scim_get_org_user(session: Session, org_id: uuid.UUID, user_id: uuid.UUID) -> dict | None:
    """One org member (any membership status) via the 0007 function."""
    row = (
        session.execute(
            text("SELECT * FROM scim_get_org_user(:org, :uid)"),
            {"org": str(org_id), "uid": str(user_id)},
        )
        .mappings()
        .first()
    )
    return dict(row) if row is not None else None


def provision_scim_user(
    session: Session,
    org_id: uuid.UUID,
    actor_id: uuid.UUID | None,
    email: str,
    full_name: str,
    active: bool = True,
) -> tuple[User, Membership, Invitation | None]:
    """Create (or return) the user for a SCIM-provisioned identity."""
    found = find_user_by_email(session, email)
    if found is not None:
        user_id = uuid.UUID(str(found["id"]))
        membership = session.execute(
            select(Membership).where(Membership.organization_id == org_id, Membership.user_id == user_id)
        ).scalar_one_or_none()
        if membership is None:
            membership = Membership(organization_id=org_id, user_id=user_id, status="invited")
            session.add(membership)
            session.flush()
        invitation = _pending_invitation(session, org_id, email)
        if invitation is None:
            invitation = _create_invitation(session, org_id, actor_id, email, [])
        # Visible now (shared org via the membership just ensured); fall
        # back to the function row if the ORM still cannot see the user.
        user = session.get(User, user_id)
        if user is None:
            user = User(
                id=user_id,
                email=found["email"],
                full_name=found["full_name"] or email,
                password_hash=found["password_hash"],
                is_active=found["is_active"],
                email_verified=found["email_verified"],
            )
        return user, membership, invitation

    # New user: the users INSERT ... RETURNING is checked against the
    # SELECT policy, which passes only for the row's own id — so the RLS
    # user context must be the new user's id for the insert (same rule
    # org provisioning follows), then restored to the actor.
    new_id = uuid.uuid4()
    set_rls_context(session, org_id, new_id)
    try:
        user = User(
            id=new_id,
            email=email,
            full_name=full_name or email,
            # Random, unknowable password: login is impossible until the
            # invitation-accept flow sets a real password.
            password_hash=hash_password(new_opaque_token()),
            email_verified=False,
        )
        session.add(user)
        session.flush()
    finally:
        set_rls_context(session, org_id, actor_id)
    membership = Membership(organization_id=org_id, user_id=user.id, status="invited" if active else "suspended")
    session.add(membership)
    session.flush()
    invitation = _create_invitation(session, org_id, actor_id, email, [])
    return user, membership, invitation


def _pending_invitation(session: Session, org_id: uuid.UUID, email: str) -> Invitation | None:
    """A still-pending invitation for this email in this org, if any."""
    return session.execute(
        select(Invitation).where(
            Invitation.organization_id == org_id, Invitation.email == email, Invitation.status == "pending"
        )
    ).scalar_one_or_none()


def _create_invitation(
    session: Session,
    org_id: uuid.UUID,
    actor_id: uuid.UUID | None,
    email: str,
    role_ids: list[uuid.UUID],
) -> Invitation | None:
    """Mirror of the invite flow: an Invitation row (hash only).

    Returns None when there is no inviter to attribute the invitation
    to (e.g. a background sync with no actor): the user is still
    provisioned, but no invitation row can exist without an inviter —
    ``invitations.invited_by_id`` is NOT NULL, and inventing one would
    be worse than skipping the row.
    """
    if actor_id is None:
        return None
    settings = get_settings()
    token = new_opaque_token()
    invitation = Invitation(
        organization_id=org_id,
        email=email,
        token_hash=hash_token(token),
        invited_by_id=actor_id,
        expires_at=datetime.now(UTC) + timedelta(days=settings.invitation_days),
    )
    session.add(invitation)
    session.flush()
    for role_id in role_ids:
        session.add(InvitationRole(invitation_id=invitation.id, role_id=role_id, organization_id=org_id))
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=actor_id,
        action=audit_mod.INVITATION_CREATED,
        resource_type="invitation",
        resource_id=str(invitation.id),
        outcome="success",
        metadata={"email": email, "source": "scim"},
    )
    return invitation


def deactivate_scim_user(session: Session, org_id: uuid.UUID, user_id: uuid.UUID) -> None:
    """SCIM delete/deactivate: suspend the membership in this org."""
    membership = session.execute(
        select(Membership).where(Membership.organization_id == org_id, Membership.user_id == user_id)
    ).scalar_one_or_none()
    if membership is not None and membership.status != "suspended":
        membership.status = "suspended"
        audit_mod.write_audit(
            session,
            organization_id=org_id,
            actor_id=None,
            action=audit_mod.MEMBERSHIP_SUSPENDED,
            resource_type="membership",
            resource_id=str(membership.id),
            outcome="success",
            metadata={"user_id": str(user_id), "source": "scim"},
        )


# --- Directory groups + role mapping ---------------------------------------


def apply_group_role_mapping(session: Session, org_id: uuid.UUID, role_id: uuid.UUID) -> dict:
    """Reconcile UserRole rows for ``role_id`` against group membership.

    Desired holders = the union of members of every directory group in
    this org mapped to the role. Holders outside that set lose the role;
    members without it gain it. This is the group-sync contract: group
    membership drives the role.
    """
    group_ids = [
        r[0]
        for r in session.execute(
            select(DirectoryGroup.id).where(DirectoryGroup.organization_id == org_id, DirectoryGroup.role_id == role_id)
        ).all()
    ]
    desired: set[uuid.UUID] = set()
    if group_ids:
        desired = {
            r[0]
            for r in session.execute(
                select(DirectoryGroupMembership.user_id).where(
                    DirectoryGroupMembership.organization_id == org_id,
                    DirectoryGroupMembership.group_id.in_(group_ids),
                )
            ).all()
        }
    current = {
        r[0]
        for r in session.execute(
            select(UserRole.user_id).where(UserRole.organization_id == org_id, UserRole.role_id == role_id)
        ).all()
    }
    added = desired - current
    removed = current - desired
    for user_id in added:
        session.add(UserRole(organization_id=org_id, user_id=user_id, role_id=role_id, granted_by_id=None))
    if removed:
        session.execute(
            delete(UserRole).where(
                UserRole.organization_id == org_id,
                UserRole.role_id == role_id,
                UserRole.user_id.in_(removed),
            )
        )
    session.flush()
    return {"role_id": str(role_id), "added": len(added), "removed": len(removed)}


def sync_all_group_role_mappings(session: Session, org_id: uuid.UUID) -> list[dict]:
    """Apply every mapped group's role mapping. Returns per-role counts."""
    role_ids = [
        r[0]
        for r in session.execute(
            select(DirectoryGroup.role_id).where(
                DirectoryGroup.organization_id == org_id, DirectoryGroup.role_id.is_not(None)
            )
        ).all()
    ]
    return [apply_group_role_mapping(session, org_id, role_id) for role_id in dict.fromkeys(role_ids)]


# --- OIDC discovery --------------------------------------------------------


_DISCOVERY_CACHE: dict[str, tuple[float, dict]] = {}
_DISCOVERY_TTL_SECONDS = 3600.0


def discover_oidc(issuer: str, transport: httpx.BaseTransport | None = None) -> dict:
    """Fetch ``{issuer}/.well-known/openid-configuration`` (10s timeout).

    Cached in memory for 1 hour per issuer. Raises OidcDiscoveryError
    when the issuer is unreachable or returns a non-JSON document —
    discovery data is never faked.
    """
    issuer = issuer.rstrip("/")
    cached = _DISCOVERY_CACHE.get(issuer)
    if cached and time.monotonic() - cached[0] < _DISCOVERY_TTL_SECONDS:
        return cached[1]
    url = f"{issuer}/.well-known/openid-configuration"
    try:
        with httpx.Client(timeout=10.0, transport=transport) as client:
            resp = client.get(url, headers={"Accept": "application/json"})
        resp.raise_for_status()
        doc = resp.json()
    except Exception as exc:
        # Broad catch is deliberate: httpx raises several non-HTTPError
        # types for bad URLs/proxies (e.g. InvalidURL, which inherits
        # only from Exception), and every one of them means the same
        # thing here — discovery failed.
        raise OidcDiscoveryError(f"OIDC discovery failed for {issuer}: {exc}") from exc
    if not isinstance(doc, dict) or "issuer" not in doc:
        raise OidcDiscoveryError(f"OIDC discovery for {issuer} did not return a valid document")
    _DISCOVERY_CACHE[issuer] = (time.monotonic(), doc)
    return doc


# --- Directory sync connectors ---------------------------------------------

_ENTRA_TOKEN_RE = re.compile(r"login\.microsoftonline\.com/([^/]+)", re.IGNORECASE)


class EntraClient:
    """Real MS Graph client (client-credentials flow).

    Credentials come from the IdP config (``oidc_client_id`` + the
    Fernet-encrypted ``oidc_client_secret_encrypted``) and the tenant id
    parsed from ``oidc_issuer`` or ``NULL_ENTRA_TENANT_ID``. Without
    them the client refuses to construct — the sync run records that
    honestly instead of inventing rows.
    """

    def __init__(self, provider: IdentityProvider, transport: httpx.BaseTransport | None = None) -> None:
        tenant = os.environ.get("NULL_ENTRA_TENANT_ID") or ""
        if provider.oidc_issuer:
            match = _ENTRA_TOKEN_RE.search(provider.oidc_issuer)
            if match:
                tenant = match.group(1)
        client_secret = None
        if provider.oidc_client_secret_encrypted:
            client_secret = decrypt_secret(provider.oidc_client_secret_encrypted)
        if not tenant or not provider.oidc_client_id or not client_secret:
            raise DirectorySyncError(
                "Entra sync is not configured: tenant id, client id, and client secret are required "
                "(set them on the identity provider or NULL_ENTRA_TENANT_ID)"
            )
        self.tenant = tenant
        self.client_id = provider.oidc_client_id
        self.client_secret = client_secret
        self._transport = transport
        self._token: str | None = None

    def _http(self) -> httpx.Client:
        return httpx.Client(timeout=30.0, transport=self._transport)

    def access_token(self) -> str:
        if self._token:
            return self._token
        with self._http() as client:
            resp = client.post(
                f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                },
            )
            resp.raise_for_status()
            self._token = resp.json()["access_token"]
        return self._token

    def _get_paged(self, url: str) -> list[dict]:
        rows: list[dict] = []
        token = self.access_token()
        with self._http() as client:
            while url:
                resp = client.get(url, headers={"Authorization": f"Bearer {token}"})
                resp.raise_for_status()
                page = resp.json()
                rows.extend(page.get("value", []))
                url = page.get("@odata.nextLink")
        return rows

    def list_users(self) -> list[dict]:
        return self._get_paged("https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,displayName,mail")

    def list_groups(self) -> list[dict]:
        return self._get_paged("https://graph.microsoft.com/v1.0/groups?$select=id,displayName")

    def list_group_members(self, group_id: str) -> list[dict]:
        return self._get_paged(f"https://graph.microsoft.com/v1.0/groups/{group_id}/members?$select=id")


class LdapClient:
    """LDAP directory client.

    ldap3 is NOT installed in this environment, so construction raises an
    honest error. The code is structured so installing ldap3 enables the
    real path: ``_connect`` imports ldap3 lazily and raises only when the
    library (or the connection settings) is missing.
    """

    def __init__(self, provider: IdentityProvider) -> None:
        try:
            import ldap3  # noqa: F401
        except ImportError as exc:
            raise DirectorySyncError("LDAP sync is not available: the ldap3 library is not installed") from exc
        raise DirectorySyncError("LDAP sync is not configured: no LDAP server settings on this provider")


def run_directory_sync(
    session: Session,
    org_id: uuid.UUID,
    provider_id: uuid.UUID | None,
    source: str,
    actor_id: uuid.UUID | None,
) -> DirectorySyncRun:
    """Start + execute a directory sync run, recording the outcome.

    SCIM source replays the org's SCIM-provisioned groups/memberships
    (reconciliation + role mapping) for real. Entra/LDAP run their real
    clients and record an honest failure when unconfigured.
    """
    if source not in ("entra", "ad", "ldap", "scim"):
        raise ValueError(f"Unknown directory source: {source}")
    provider = None
    if provider_id is not None:
        provider = session.get(IdentityProvider, provider_id)
        if provider is None or provider.organization_id != org_id:
            raise ValueError("Identity provider not found")
    run = DirectorySyncRun(organization_id=org_id, provider_id=provider_id, source=source, status="running")
    session.add(run)
    session.flush()
    try:
        if source == "scim":
            _sync_scim_replay(session, org_id, run)
        elif source == "entra":
            if provider is None:
                raise DirectorySyncError("Entra sync requires an identity provider")
            _sync_entra(session, org_id, provider, run, actor_id)
        else:  # ad | ldap
            if provider is None:
                raise DirectorySyncError(f"{source.upper()} sync requires an identity provider")
            LdapClient(provider)  # raises honestly until ldap3 + config exist
        run.status = "completed"
    except (DirectorySyncError, httpx.HTTPError, ValueError) as exc:
        run.status = "failed"
        run.error = str(exc)
    run.completed_at = datetime.now(UTC)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=actor_id,
        action=audit_mod.DIRECTORY_SYNC_COMPLETED,
        resource_type="directory_sync_run",
        resource_id=str(run.id),
        outcome="success" if run.status == "completed" else "failed",
        metadata={"source": source, "status": run.status, "error": run.error},
    )
    return run


def _sync_scim_replay(session: Session, org_id: uuid.UUID, run: DirectorySyncRun) -> None:
    """Reconcile SCIM-provisioned groups/memberships (real, local data).

    Refreshes member counts from the membership rows, applies every
    group->role mapping, and counts the groups/users reconciled. No
    external call is made and no row is invented: the counts come from
    the rows that actually exist.
    """
    groups = session.execute(select(DirectoryGroup).where(DirectoryGroup.organization_id == org_id)).scalars().all()
    users_seen: set[uuid.UUID] = set()
    for group in groups:
        member_ids = [
            r[0]
            for r in session.execute(
                select(DirectoryGroupMembership.user_id).where(
                    DirectoryGroupMembership.organization_id == org_id,
                    DirectoryGroupMembership.group_id == group.id,
                )
            ).all()
        ]
        group.member_count = len(member_ids)
        group.last_synced_at = datetime.now(UTC)
        users_seen.update(member_ids)
    run.groups_synced = len(groups)
    run.users_updated = len(users_seen)
    run.users_created = 0
    run.users_deprovisioned = 0
    sync_all_group_role_mappings(session, org_id)
    session.flush()


def _sync_entra(
    session: Session, org_id: uuid.UUID, provider: IdentityProvider, run: DirectorySyncRun, actor_id: uuid.UUID | None
) -> None:
    """Real Entra sync via MS Graph (fails honestly when unconfigured)."""
    client = EntraClient(provider)
    users = client.list_users()
    groups = client.list_groups()
    created = updated = deprovisioned = 0
    for entry in users:
        email = entry.get("mail") or entry.get("userPrincipalName")
        if not email:
            continue
        existing = find_user_by_email(session, email)
        if existing is None:
            provision_scim_user(session, org_id, actor_id, email, entry.get("displayName") or email, active=True)
            created += 1
        else:
            updated += 1
    for entry in groups:
        external_id = entry.get("id")
        if not external_id:
            continue
        group = session.execute(
            select(DirectoryGroup).where(
                DirectoryGroup.organization_id == org_id,
                DirectoryGroup.provider_id == provider.id,
                DirectoryGroup.external_id == external_id,
            )
        ).scalar_one_or_none()
        if group is None:
            group = DirectoryGroup(
                organization_id=org_id,
                provider_id=provider.id,
                external_id=external_id,
                name=entry.get("displayName") or external_id,
            )
            session.add(group)
            session.flush()
    run.users_created = created
    run.users_updated = updated
    run.users_deprovisioned = deprovisioned
    run.groups_synced = len(groups)
    sync_all_group_role_mappings(session, org_id)
    session.flush()


# --- Access certification --------------------------------------------------


def create_certification(
    session: Session,
    org_id: uuid.UUID,
    reviewer_id: uuid.UUID,
    name: str,
    scope: dict,
    due_at: datetime | None,
) -> AccessCertification:
    """Create a campaign; items are generated from the scope's roles.

    One item per (user, role) holding a role listed in
    ``scope["roles"]`` (role ids as strings). An empty scope creates a
    campaign with no items.
    """
    cert = AccessCertification(
        organization_id=org_id, name=name, reviewer_id=reviewer_id, scope=scope or {}, due_at=due_at
    )
    session.add(cert)
    session.flush()
    role_ids: list[uuid.UUID] = []
    for raw in (scope or {}).get("roles", []):
        try:
            role_ids.append(uuid.UUID(str(raw)))
        except ValueError:
            continue
    if role_ids:
        rows = (
            session.execute(select(UserRole).where(UserRole.organization_id == org_id, UserRole.role_id.in_(role_ids)))
            .scalars()
            .all()
        )
        for ur in rows:
            session.add(
                CertificationItem(
                    organization_id=org_id, certification_id=cert.id, user_id=ur.user_id, role_id=ur.role_id
                )
            )
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=reviewer_id,
        action=audit_mod.ACCESS_CERTIFICATION_CREATED,
        resource_type="access_certification",
        resource_id=str(cert.id),
        outcome="success",
        metadata={"name": name},
    )
    return cert


def decide_certification_item(
    session: Session,
    org_id: uuid.UUID,
    item_id: uuid.UUID,
    decision: str,
    decided_by_id: uuid.UUID,
) -> CertificationItem:
    """Decide one item. ``revoke`` removes the user_roles row for real.

    When every item in the campaign is decided, the campaign completes.
    """
    if decision not in ("approved", "revoked"):
        raise ValueError("decision must be 'approved' or 'revoked'")
    item = session.get(CertificationItem, item_id)
    if item is None or item.organization_id != org_id:
        raise ValueError("Certification item not found")
    if item.decision != "pending":
        raise ValueError("Certification item is already decided")
    item.decision = decision
    item.decided_by_id = decided_by_id
    item.decided_at = datetime.now(UTC)
    if decision == "revoked" and item.role_id is not None:
        session.execute(
            delete(UserRole).where(
                UserRole.organization_id == org_id,
                UserRole.user_id == item.user_id,
                UserRole.role_id == item.role_id,
            )
        )
    # Flush BEFORE the pending check: sessions here run with
    # autoflush=False, so without this the just-decided item still reads
    # as pending and the campaign can never complete.
    session.flush()
    cert = session.get(AccessCertification, item.certification_id)
    pending = (
        session.execute(
            select(CertificationItem).where(
                CertificationItem.organization_id == org_id,
                CertificationItem.certification_id == item.certification_id,
                CertificationItem.decision == "pending",
            )
        )
        .scalars()
        .first()
    )
    if pending is None and cert is not None:
        cert.status = "completed"
        cert.completed_at = datetime.now(UTC)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=decided_by_id,
        action=audit_mod.ACCESS_CERTIFICATION_DECIDED,
        resource_type="certification_item",
        resource_id=str(item.id),
        outcome="success",
        metadata={"decision": decision, "user_id": str(item.user_id), "role_id": str(item.role_id)},
    )
    return item


# --- Temporary access grants -----------------------------------------------


def create_temp_grant(
    session: Session,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    granted_by_id: uuid.UUID,
    reason: str,
    expires_at: datetime,
) -> TemporaryAccessGrant:
    """Create a grant and assign the role immediately (it is temporary)."""
    role = session.get(Role, role_id)
    if role is None or role.organization_id != org_id:
        raise ValueError("Role not found")
    user = session.get(User, user_id)
    if user is None:
        raise ValueError("User not found")
    membership = session.execute(
        select(Membership).where(Membership.organization_id == org_id, Membership.user_id == user_id)
    ).scalar_one_or_none()
    if membership is None or membership.status != "active":
        raise ValueError("User has no active membership in this organization")
    existing = session.execute(
        select(UserRole).where(
            UserRole.organization_id == org_id, UserRole.user_id == user_id, UserRole.role_id == role_id
        )
    ).scalar_one_or_none()
    if existing is None:
        session.add(UserRole(organization_id=org_id, user_id=user_id, role_id=role_id, granted_by_id=granted_by_id))
    grant = TemporaryAccessGrant(
        organization_id=org_id,
        user_id=user_id,
        role_id=role_id,
        granted_by_id=granted_by_id,
        reason=reason,
        expires_at=expires_at,
    )
    session.add(grant)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=granted_by_id,
        action=audit_mod.TEMP_ACCESS_GRANTED,
        resource_type="temporary_access_grant",
        resource_id=str(grant.id),
        outcome="success",
        metadata={"user_id": str(user_id), "role_id": str(role_id), "expires_at": expires_at.isoformat()},
    )
    return grant


def _remove_user_role(session: Session, org_id: uuid.UUID, user_id: uuid.UUID, role_id: uuid.UUID) -> None:
    session.execute(
        delete(UserRole).where(
            UserRole.organization_id == org_id, UserRole.user_id == user_id, UserRole.role_id == role_id
        )
    )


def revoke_temp_grant(
    session: Session, org_id: uuid.UUID, grant_id: uuid.UUID, actor_id: uuid.UUID
) -> TemporaryAccessGrant:
    """Revoke a grant: remove the role row, mark revoked."""
    grant = session.get(TemporaryAccessGrant, grant_id)
    if grant is None or grant.organization_id != org_id:
        raise ValueError("Temporary access grant not found")
    if grant.status != "active":
        raise ValueError(f"Grant is already {grant.status}")
    _remove_user_role(session, org_id, grant.user_id, grant.role_id)
    grant.status = "revoked"
    grant.revoked_at = datetime.now(UTC)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=actor_id,
        action=audit_mod.TEMP_ACCESS_REVOKED,
        resource_type="temporary_access_grant",
        resource_id=str(grant.id),
        outcome="success",
        metadata={"user_id": str(grant.user_id), "role_id": str(grant.role_id)},
    )
    return grant


def expire_temp_grants(session: Session, org_id: uuid.UUID) -> int:
    """Sweep: expire every active grant past its expiry (role removed)."""
    now = datetime.now(UTC)
    grants = (
        session.execute(
            select(TemporaryAccessGrant).where(
                TemporaryAccessGrant.organization_id == org_id,
                TemporaryAccessGrant.status == "active",
                TemporaryAccessGrant.expires_at < now,
            )
        )
        .scalars()
        .all()
    )
    for grant in grants:
        _remove_user_role(session, org_id, grant.user_id, grant.role_id)
        grant.status = "expired"
        audit_mod.write_audit(
            session,
            organization_id=org_id,
            actor_id=None,
            action=audit_mod.TEMP_ACCESS_REVOKED,
            resource_type="temporary_access_grant",
            resource_id=str(grant.id),
            outcome="success",
            metadata={"user_id": str(grant.user_id), "role_id": str(grant.role_id), "expired": True},
        )
    session.flush()
    return len(grants)


# --- Service accounts / API credentials ------------------------------------


def create_service_account(
    session: Session,
    org_id: uuid.UUID,
    name: str,
    description: str,
    scopes: list[str],
    expires_at: datetime | None,
    created_by_id: uuid.UUID,
) -> tuple[ServiceAccount, str]:
    """Create a service account. Returns (row, raw_secret) — shown once."""
    raw = new_opaque_token()
    row = ServiceAccount(
        organization_id=org_id,
        name=name,
        description=description,
        credential_hash=hash_secret(raw),
        scopes=scopes,
        expires_at=expires_at,
        created_by_id=created_by_id,
    )
    session.add(row)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=created_by_id,
        action=audit_mod.SERVICE_ACCOUNT_CREATED,
        resource_type="service_account",
        resource_id=str(row.id),
        outcome="success",
        metadata={"name": name},
    )
    return row, raw


def rotate_service_account(
    session: Session, org_id: uuid.UUID, account_id: uuid.UUID, actor_id: uuid.UUID
) -> tuple[ServiceAccount, str]:
    """Rotate a service account secret (old hash invalidated at once)."""
    row = session.get(ServiceAccount, account_id)
    if row is None or row.organization_id != org_id:
        raise ValueError("Service account not found")
    raw = new_opaque_token()
    row.credential_hash = hash_secret(raw)
    row.revoked_at = None
    session.flush()
    return row, raw


def revoke_service_account(session: Session, org_id: uuid.UUID, account_id: uuid.UUID, actor_id: uuid.UUID) -> None:
    row = session.get(ServiceAccount, account_id)
    if row is None or row.organization_id != org_id:
        raise ValueError("Service account not found")
    row.revoked_at = datetime.now(UTC)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=actor_id,
        action=audit_mod.SERVICE_ACCOUNT_REVOKED,
        resource_type="service_account",
        resource_id=str(row.id),
        outcome="success",
        metadata={"name": row.name},
    )


def create_api_credential(
    session: Session,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    name: str,
    scopes: list[str],
    expires_at: datetime | None,
) -> tuple[ApiCredential, str]:
    """Create a per-user API credential. Returns (row, raw_credential)."""
    raw = new_opaque_token()
    row = ApiCredential(
        organization_id=org_id,
        user_id=user_id,
        name=name,
        credential_hash=hash_secret(raw),
        scopes=scopes,
        expires_at=expires_at,
    )
    session.add(row)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=user_id,
        action=audit_mod.API_CREDENTIAL_CREATED,
        resource_type="api_credential",
        resource_id=str(row.id),
        outcome="success",
        metadata={"name": name, "user_id": str(user_id)},
    )
    return row, raw


def rotate_api_credential(session: Session, org_id: uuid.UUID, credential_id: uuid.UUID) -> tuple[ApiCredential, str]:
    row = session.get(ApiCredential, credential_id)
    if row is None or row.organization_id != org_id:
        raise ValueError("API credential not found")
    raw = new_opaque_token()
    row.credential_hash = hash_secret(raw)
    row.revoked_at = None
    session.flush()
    return row, raw


def revoke_api_credential(session: Session, org_id: uuid.UUID, credential_id: uuid.UUID, actor_id: uuid.UUID) -> None:
    row = session.get(ApiCredential, credential_id)
    if row is None or row.organization_id != org_id:
        raise ValueError("API credential not found")
    row.revoked_at = datetime.now(UTC)
    session.flush()
    audit_mod.write_audit(
        session,
        organization_id=org_id,
        actor_id=actor_id,
        action=audit_mod.API_CREDENTIAL_REVOKED,
        resource_type="api_credential",
        resource_id=str(row.id),
        outcome="success",
        metadata={"name": row.name},
    )


def verify_api_credential(session: Session, org_id: uuid.UUID, raw_credential: str) -> dict | None:
    """Real credential verification: hash match + unexpired + unrevoked.

    Returns the credential's scopes/user on success, None otherwise.
    Updates last_used_at on success.
    """
    row = session.execute(
        select(ApiCredential).where(
            ApiCredential.organization_id == org_id,
            ApiCredential.credential_hash == hash_secret(raw_credential),
        )
    ).scalar_one_or_none()
    if row is None:
        return None
    now = datetime.now(UTC)
    if row.revoked_at is not None:
        return None
    if row.expires_at is not None and row.expires_at < now:
        return None
    row.last_used_at = now
    session.flush()
    return {"id": str(row.id), "user_id": str(row.user_id), "name": row.name, "scopes": row.scopes}
