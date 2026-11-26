"""Cryptographic primitives: password hashing, tokens, TOTP, JWT, OIDC.

Rules enforced here:
- Passwords are hashed with Argon2id (OWASP-recommended). Plaintext
  passwords are never stored or logged.
- Refresh / invitation / reset tokens are stored only as SHA-256 hashes.
- Access tokens are short-lived JWTs. In production they are RS256 OIDC
  tokens verified against the issuer's JWKS (Cognito); in local development
  they are HS256 tokens signed with ``NULL_JWT_SECRET``.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.config import get_settings

_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)


# --- Passwords -----------------------------------------------------------


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


# --- Opaque tokens (refresh / invitation / reset) ------------------------


def new_opaque_token() -> str:
    """A URL-safe random token. Only its hash is ever persisted."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --- TOTP (MFA) ----------------------------------------------------------


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str, issuer: str = "NULL ITSM") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:
        return False


# --- JWT (local dev issuer) ----------------------------------------------


@dataclass
class TokenClaims:
    sub: str  # user id
    org: str | None  # organization id (None until org is chosen)
    email: str
    exp: int
    iat: int
    type: str = "access"  # access | mfa | reset | platform_access | platform_mfa
    mfa: bool = False  # platform tokens only: whether MFA was completed


def _local_secret() -> str:
    settings = get_settings()
    return settings.jwt_secret


def issue_access_token(user_id, org_id, email: str) -> str:
    """Issue a local dev access token.

    ``user_id``/``org_id`` may be UUID objects (psycopg) or strings (API
    input) — JWT claims must be JSON strings, so coerce here.
    """
    settings = get_settings()
    now = int(time.time())
    claims = {
        "sub": str(user_id),
        "org": str(org_id) if org_id is not None else None,
        "email": email,
        "type": "access",
        "iat": now,
        "exp": now + settings.access_token_minutes * 60,
    }
    return jwt.encode(claims, _local_secret(), algorithm=settings.jwt_algorithm)


def issue_mfa_token(user_id, email: str) -> str:
    settings = get_settings()
    now = int(time.time())
    claims = {
        "sub": str(user_id),
        "org": None,
        "email": email,
        "type": "mfa",
        "iat": now,
        "exp": now + settings.mfa_token_minutes * 60,
    }
    return jwt.encode(claims, _local_secret(), algorithm=settings.jwt_algorithm)


def issue_org_select_token(user_id, email: str) -> str:
    """Short-lived token that may ONLY call select-organization.

    Issued when a user belongs to several organizations: they must prove
    their credentials (login/MFA) first, then choose an organization.
    """
    settings = get_settings()
    now = int(time.time())
    claims = {
        "sub": str(user_id),
        "org": None,
        "email": email,
        "type": "org_select",
        "iat": now,
        "exp": now + settings.mfa_token_minutes * 60,
    }
    return jwt.encode(claims, _local_secret(), algorithm=settings.jwt_algorithm)


def issue_platform_access_token(platform_user_id, email: str, mfa: bool) -> str:
    """Issue a platform-domain access token (type ``platform_access``).

    A DISTINCT JWT type from the org ``access`` token: an org token can
    never authenticate a platform endpoint and vice versa — the type
    check in :func:`decode_local_token` rejects the other domain.
    ``mfa`` records whether MFA was completed for this session; every
    ``*:manage`` platform permission requires it to be true.
    """
    settings = get_settings()
    now = int(time.time())
    claims = {
        "sub": str(platform_user_id),
        "org": None,
        "email": email,
        "type": "platform_access",
        "mfa": bool(mfa),
        "iat": now,
        "exp": now + settings.access_token_minutes * 60,
    }
    return jwt.encode(claims, _local_secret(), algorithm=settings.jwt_algorithm)


def issue_platform_mfa_token(platform_user_id, email: str) -> str:
    settings = get_settings()
    now = int(time.time())
    claims = {
        "sub": str(platform_user_id),
        "org": None,
        "email": email,
        "type": "platform_mfa",
        "iat": now,
        "exp": now + settings.mfa_token_minutes * 60,
    }
    return jwt.encode(claims, _local_secret(), algorithm=settings.jwt_algorithm)


def decode_local_token(token: str, expected_type: str = "access") -> TokenClaims:
    settings = get_settings()
    payload = jwt.decode(
        token, _local_secret(), algorithms=[settings.jwt_algorithm], options={"require": ["exp", "iat", "sub"]}
    )
    if payload.get("type", "access") != expected_type:
        raise jwt.InvalidTokenError(f"wrong token type: {payload.get('type')}")
    return TokenClaims(
        sub=payload["sub"],
        org=payload.get("org"),
        email=payload.get("email", ""),
        exp=payload["exp"],
        iat=payload["iat"],
        type=payload.get("type", "access"),
        mfa=bool(payload.get("mfa", False)),
    )


# --- OIDC / Cognito verification (production) ----------------------------


class OIDCVerifier:
    """Verifies RS256 OIDC tokens against an issuer's JWKS.

    In production ``NULL_OIDC_ISSUER`` points at the Cognito user-pool
    issuer (https://cognito-idp.<region>.amazonaws.com/<pool-id>) and the
    JWKS URL is ``<issuer>/.well-known/jwks.json``. The local dev issuer is
    used when no OIDC issuer is configured.
    """

    def __init__(self, issuer: str, audience: str, jwks_url: str) -> None:
        self.issuer = issuer
        self.audience = audience
        self.jwks_url = jwks_url
        self._jwks_client = jwt.PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=3600)

    def verify(self, token: str) -> TokenClaims:
        signing_key = self._jwks_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=self.issuer,
            audience=self.audience or None,
            options={"require": ["exp", "iat", "sub"]},
        )
        return TokenClaims(
            sub=payload["sub"],
            org=payload.get("custom:org_id") or payload.get("org"),
            email=payload.get("email", ""),
            exp=payload["exp"],
            iat=payload["iat"],
            type=payload.get("token_use", "access"),
        )


def get_token_verifier():
    """Return the configured verifier: OIDC (Cognito) or local dev JWT."""
    settings = get_settings()
    if settings.oidc_enabled:
        return OIDCVerifier(settings.oidc_issuer, settings.oidc_audience, settings.oidc_jwks_url)
    return None  # local HS256 path via decode_local_token
