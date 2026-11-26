"""Field-level encryption for secrets stored in the database.

Mailbox passwords (and future per-org secrets) are encrypted with Fernet
(AES-128-CBC + HMAC, via ``cryptography``) under the key configured as
``NULL_FIELD_ENCRYPTION_KEY`` (``settings.field_encryption_key``).

Fail closed: when no key is configured both functions raise
``RuntimeError`` — callers must never fall back to plaintext storage.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings


def _fernet() -> Fernet:
    key = get_settings().field_encryption_key
    if not key:
        raise RuntimeError("field encryption is not configured")
    try:
        return Fernet(key.encode("utf-8"))
    except Exception as exc:  # invalid base64 / wrong key length
        raise RuntimeError("field encryption key is invalid") from exc


def encrypt(plaintext: str) -> str:
    """Encrypt ``plaintext`` and return the Fernet token as text."""
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt(ciphertext: str) -> str:
    """Decrypt a token produced by :func:`encrypt`."""
    try:
        return _fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError("field decryption failed") from exc
