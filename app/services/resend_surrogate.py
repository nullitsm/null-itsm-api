"""Resend API key via the Muse dynamic-credential surrogate.

On this VM the Resend key lives in secure storage; no process can read
its value — not the parent agent, not this backend. authd hands out an
``hsurr:`` surrogate for the registered ``custom.resend`` credential,
and the VM's egress proxy swaps the surrogate for the real key on
approved requests to api.resend.com. The backend therefore never sees,
stores, logs, or transmits the real key: it fetches a fresh surrogate
per send and puts THAT in the Authorization header. The request MUST
route through the egress proxy (explicit ``proxy=`` on the httpx
client); sent direct, the surrogate reaches Resend unswapped and is
rejected with 401.

This module is the backend's only contact with authd. It imports the
bundled helper (the same one the custom.resend connector helpers use)
so the surrogate protocol lives in exactly one place. When the helper
or the socket is absent (a real production host), surrogate mode is
simply unavailable and the caller fails closed.
"""

from __future__ import annotations

import importlib.util
import os

CREDENTIAL_NAME = "custom.resend"
ENTRY_NAME = "access_token"
ALLOWED_HOSTS = ("api.resend.com",)
DEFAULT_HELPER_PATH = "/opt/muse/skills/custom-connector-setup/bin/dynamic_credentials.py"
DEFAULT_SOCKET_PATH = "/run/hatch/auth/authd.sock"


class SurrogateUnavailable(RuntimeError):
    """The surrogate channel is unavailable (no helper, no socket, no credential)."""


def _load_helper():
    path = os.environ.get("NULL_DYNAMIC_CREDENTIALS_PATH", DEFAULT_HELPER_PATH)
    spec = importlib.util.spec_from_file_location("null_dynamic_credentials", path)
    if spec is None or spec.loader is None:
        raise SurrogateUnavailable(f"dynamic credentials helper not found at {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _socket_path() -> str:
    return os.environ.get("JARVIS_AUTHD_SOCK", DEFAULT_SOCKET_PATH)


def surrogate_channel_available() -> bool:
    """True when the authd socket exists — the cheap availability probe.

    This proves the channel is present, not that the credential is
    registered; the send itself is the real proof (a missing credential
    fails loudly as a configuration error). No surrogate is consumed.
    """
    return os.path.exists(_socket_path())


def fetch_resend_surrogate(socket_path: str | None = None) -> str:
    """Fetch a fresh surrogate for the Resend credential.

    One surrogate per send; never cached or reused across sends, and
    never logged or stored — it is a bearer credential for exactly one
    approved egress.
    """
    try:
        helper = _load_helper()
    except (OSError, ImportError) as exc:
        raise SurrogateUnavailable(f"cannot load dynamic credentials helper: {exc}") from exc
    try:
        entry = helper.dynamic_credential_entry(
            CREDENTIAL_NAME, ENTRY_NAME, socket_path=socket_path or _socket_path()
        )
    except (OSError, RuntimeError) as exc:
        # DynamicCredentialError is a RuntimeError; socket failures are
        # OSError. Either way the channel is unavailable right now.
        raise SurrogateUnavailable(f"authd surrogate unavailable: {exc}") from exc
    surrogate = str(entry.get("surrogate", "")).strip()
    placement = entry.get("placement")
    if not surrogate.startswith("hsurr:"):
        raise SurrogateUnavailable("authd returned a non-surrogate value for custom.resend")
    if placement != "bearer_header":
        raise SurrogateUnavailable(f"unexpected surrogate placement for custom.resend: {placement!r}")
    return surrogate
