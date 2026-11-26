"""SAML service: SP metadata generation + assertion validation.

Two pieces:
- :func:`build_sp_metadata` builds real SP metadata XML from the org's
  configured identity provider (entityID, ACS URL). A signing
  KeyDescriptor is included ONLY when a certificate is actually
  configured; otherwise the metadata says so in an XML comment — a
  certificate is never invented.
- :class:`SamlValidator` is the assertion-validation interface. The real
  implementation (:class:`OneLoginSamlValidator`) uses python3-saml.
  :class:`StubSamlValidator` exists so tests can exercise the ACS wiring
  without a real IdP. An assertion is NEVER accepted unless a validator
  says it is valid: no validator / no IdP certificate / failed signature
  all refuse the login.
"""

from __future__ import annotations

import base64
import html
import uuid
from typing import Protocol

from app.models.identity_assets import IdentityProvider

# python3-saml is an optional dependency: the ACS endpoint must fail
# honestly (501) when it is not installed, never fake a validation.
try:  # pragma: no cover - import probe
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.settings import OneLogin_Saml2_Settings

    _SAML_LIB_AVAILABLE = True
except ImportError:  # pragma: no cover - import probe
    OneLogin_Saml2_Auth = None  # type: ignore[assignment]
    OneLogin_Saml2_Settings = None  # type: ignore[assignment]
    _SAML_LIB_AVAILABLE = False


def saml_lib_available() -> bool:
    """Whether python3-saml is importable in this environment."""
    return _SAML_LIB_AVAILABLE


class SamlValidationError(Exception):
    """The SAML response could not be validated (or was invalid)."""


class SamlValidator(Protocol):
    """Validate a base64 SAMLResponse for a provider.

    Returns ``{"name_id": ..., "email": ..., "attributes": {...}}`` on
    success; raises :class:`SamlValidationError` otherwise.
    """

    def validate(self, response_b64: str, provider: IdentityProvider, acs_url: str) -> dict: ...


class OneLoginSamlValidator:
    """Real validator backed by python3-saml (OneLogin_Saml2_Auth)."""

    def validate(self, response_b64: str, provider: IdentityProvider, acs_url: str) -> dict:
        if not _SAML_LIB_AVAILABLE:
            raise SamlValidationError("SAML assertion validation requires python3-saml (not installed)")
        if not provider.saml_certificate:
            raise SamlValidationError(
                "SAML provider has no IdP certificate configured; the assertion cannot be verified"
            )
        if not provider.saml_sso_url or not provider.saml_entity_id:
            raise SamlValidationError("SAML provider is missing its entity ID or SSO URL")
        try:
            raw = base64.b64decode(response_b64, validate=True)
        except Exception as exc:
            raise SamlValidationError("SAMLResponse is not valid base64") from exc
        if b"<saml" not in raw.lower() and b"<samlp" not in raw.lower():
            raise SamlValidationError("SAMLResponse does not contain a SAML document")

        entity_id = provider.saml_entity_id
        settings_data = {
            "strict": True,
            "debug": False,
            "sp": {
                "entityId": entity_id,
                "assertionConsumerService": {
                    "url": acs_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
            },
            "idp": {
                "entityId": provider.saml_entity_id,
                "singleSignOnService": {
                    "url": provider.saml_sso_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "x509cert": provider.saml_certificate,
            },
        }
        request_data = {
            "http_host": "localhost",
            "script_name": "/api/v1/identity/providers/acs",
            "server_port": 443,
            "get_data": {},
            "post_data": {"SAMLResponse": response_b64},
        }
        try:
            auth = OneLogin_Saml2_Auth(request_data, settings_data)
            auth.process_response()
        except Exception as exc:
            raise SamlValidationError(f"SAML response processing failed: {exc}") from exc
        errors = auth.get_errors()
        if errors or not auth.is_authenticated():
            raise SamlValidationError(f"SAML assertion failed validation: {errors or 'not authenticated'}")
        attributes = auth.get_attributes() or {}
        flat = {k: (v[0] if isinstance(v, list) and v else v) for k, v in attributes.items()}
        name_id = auth.get_nameid()
        email = flat.get("email") or flat.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
        if not email and name_id and "@" in name_id:
            email = name_id
        if not name_id:
            raise SamlValidationError("SAML assertion carries no NameID")
        return {"name_id": name_id, "email": email, "attributes": flat}


class StubSamlValidator:
    """Test-only validator: accepts exactly one canned response.

    ``mapping`` maps a base64 SAMLResponse to the validated identity dict.
    Anything else raises — it never accepts an arbitrary assertion.
    """

    def __init__(self, mapping: dict[str, dict] | None = None) -> None:
        self.mapping = mapping or {}

    def validate(self, response_b64: str, provider: IdentityProvider, acs_url: str) -> dict:
        result = self.mapping.get(response_b64)
        if result is None:
            raise SamlValidationError("stub validator: unknown SAMLResponse")
        return result


def get_saml_validator() -> SamlValidator:
    """Return the validator the ACS endpoint uses (real one by default)."""
    return OneLoginSamlValidator()


def build_sp_metadata(
    provider: IdentityProvider,
    org_id: uuid.UUID,
    base_url: str,
    signing_cert: str | None = None,
) -> str:
    """Build SP metadata XML for ``provider``.

    ``entityID`` is the provider's configured ``saml_entity_id`` when set,
    otherwise a stable URL derived from the org id. The ACS URL is the
    provider's ACS endpoint under ``base_url``. ``signing_cert`` is the
    SP's own signing certificate — only ever supplied from configuration;
    when it is None the KeyDescriptor is omitted and the XML says so in a
    comment (a certificate is never invented).
    """
    base = base_url.rstrip("/")
    entity_id = provider.saml_entity_id or f"{base}/api/v1/identity/saml/sp/{org_id}"
    acs_url = f"{base}/api/v1/identity/providers/{provider.id}/acs"
    entity_id_e = html.escape(entity_id, quote=True)
    acs_e = html.escape(acs_url, quote=True)
    if signing_cert:
        key_descriptor = (
            '  <md:KeyDescriptor use="signing">\n'
            '    <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\n'
            "      <ds:X509Data>\n"
            f"        <ds:X509Certificate>{html.escape(signing_cert.strip())}</ds:X509Certificate>\n"
            "      </ds:X509Data>\n"
            "    </ds:KeyInfo>\n"
            "  </md:KeyDescriptor>\n"
        )
    else:
        key_descriptor = (
            "  <!-- No SP signing certificate is configured for this provider, "
            "so no KeyDescriptor is included. Configure one before requiring "
            "signed AuthnRequests. -->\n"
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="{entity_id_e}">\n'
        '  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n'
        f"{key_descriptor}"
        "    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>\n"
        "    <md:AssertionConsumerService "
        'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'Location="{acs_e}" index="1"/>\n'
        "  </md:SPSSODescriptor>\n"
        "</md:EntityDescriptor>\n"
    )
