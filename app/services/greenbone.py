"""Pure-Python Greenbone Management Protocol (GMP) client.

No ``gvm-tools`` / Greenbone package is installed in this environment, so
the client speaks GMP directly over TLS with the standard library only
(``ssl`` + ``socket`` + ``xml.etree``). It never invents results: every
failure to connect, authenticate, or parse a response raises
:class:`GreenboneError`, and callers must surface that honestly
("engine unreachable" / "engine authentication failed").

Protocol notes
--------------
* GMP is one XML document per request/response over a single TLS
  connection (default port 9390). A response is read until it parses
  as a complete XML document.
* The standard "Full and Fast" scan config UUID is
  ``daba56c8-73ec-11df-a475-002264764cea`` (documented here so the
  magic value is never silently re-typed elsewhere).
* The default OpenVAS scanner UUID is
  ``08b69003-5fc2-4037-a479-93b440211c73`` and the "All IANA assigned
  TCP" port list is ``33d0cd82-57c6-11e1-8ed1-406186ea4fc5``.
* Severity is reported by Greenbone as a numeric CVSS-style score and
  is normalised to the ``critical | high | medium | low | none`` band
  used by the vulnerability tables.

Testability: the constructor takes an injectable ``socket_factory``
``(host, port, timeout) -> socket-like`` so tests can stub the
transport with a clearly-labelled test double. The default factory
opens a real TLS socket.
"""

from __future__ import annotations

import socket
import ssl
import xml.etree.ElementTree as ET
from typing import Callable
from xml.sax.saxutils import escape

# Standard Greenbone scan config: "Full and Fast".
FULL_AND_FAST_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
# Default OpenVAS scanner.
DEFAULT_SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"
# "All IANA assigned TCP" port list.
ALL_TCP_PORT_LIST_ID = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"

DEFAULT_GMP_PORT = 9390


class GreenboneError(Exception):
    """The engine could not be reached, refused auth, or returned
    unusable XML. Never a stand-in for scan results."""


def severity_from_score(score: float | None) -> str:
    """Map a numeric CVSS-style score to a severity band."""
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _default_socket_factory(host: str, port: int, timeout: float):
    """Open a real TLS socket to ``host:port``."""
    raw = socket.create_connection((host, port), timeout=timeout)
    context = ssl.create_default_context()
    return context.wrap_socket(raw, server_hostname=host)


class GreenboneClient:
    """Minimal GMP client (connect / authenticate / tasks / reports)."""

    def __init__(
        self,
        host: str,
        port: int = DEFAULT_GMP_PORT,
        username: str | None = None,
        password: str | None = None,
        *,
        socket_factory: Callable[[str, int, float], object] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self._socket_factory = socket_factory or _default_socket_factory
        self.timeout = timeout
        self._sock = None
        self._authenticated = False

    # -- connection ------------------------------------------------------

    def connect(self) -> None:
        """Open the TLS connection (no auth yet)."""
        if self._sock is not None:
            return
        try:
            self._sock = self._socket_factory(self.host, self.port, self.timeout)
        except (OSError, ssl.SSLError) as exc:
            raise GreenboneError(f"engine unreachable: {self.host}:{self.port}: {exc}") from exc

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
            self._authenticated = False

    def __enter__(self) -> "GreenboneClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- low-level request/response --------------------------------------

    def _request(self, xml: str) -> ET.Element:
        """Send one GMP request and return the parsed response element.

        Reads until the accumulated bytes parse as a complete XML
        document; a closed connection or unparseable stream is an error.
        """
        self.connect()
        try:
            self._sock.sendall(xml.encode("utf-8"))
        except (OSError, ssl.SSLError) as exc:
            raise GreenboneError(f"engine unreachable while sending request: {exc}") from exc
        buf = b""
        try:
            while True:
                chunk = self._sock.recv(65536)
                if not chunk:
                    raise GreenboneError("engine closed the connection before sending a complete response")
                buf += chunk
                try:
                    return ET.fromstring(buf)
                except ET.ParseError:
                    if len(buf) > 64 * 1024 * 1024:
                        raise GreenboneError("engine response exceeded 64 MiB without parsing as XML")
                    continue
        except GreenboneError:
            raise
        except (OSError, ssl.SSLError) as exc:
            raise GreenboneError(f"engine unreachable while reading response: {exc}") from exc

    @staticmethod
    def _check_status(root: ET.Element, what: str) -> None:
        status = root.get("status")
        if status is None or not status.startswith("2"):
            raise GreenboneError(f"{what} failed: status={status or '?'} status_text={root.get('status_text') or '?'}")

    # -- auth ------------------------------------------------------------

    def authenticate(self) -> bool:
        """Authenticate with the configured username/password."""
        if not self.username or not self.password:
            raise GreenboneError("engine authentication failed: no credentials configured")
        xml = (
            "<authenticate><credentials>"
            f"<username>{escape(self.username)}</username>"
            f"<password>{escape(self.password)}</password>"
            "</credentials></authenticate>"
        )
        root = self._request(xml)
        self._check_status(root, "authenticate")
        self._authenticated = True
        return True

    def _ensure_authenticated(self) -> None:
        if not self._authenticated:
            self.authenticate()

    # -- targets / tasks ---------------------------------------------------

    def create_target(self, name: str, hosts: str) -> str:
        """Create a scan target; returns the target UUID."""
        self._ensure_authenticated()
        xml = (
            "<create_target>"
            f"<name>{escape(name)}</name>"
            f"<hosts>{escape(hosts)}</hosts>"
            f'<port_list id="{ALL_TCP_PORT_LIST_ID}"/>'
            "</create_target>"
        )
        root = self._request(xml)
        self._check_status(root, "create_target")
        target_id = root.findtext("id")
        if not target_id:
            raise GreenboneError("create_target response contained no target id")
        return target_id

    def create_task(
        self,
        name: str,
        target_id: str,
        config_id: str = FULL_AND_FAST_CONFIG_ID,
    ) -> str:
        """Create a scan task on ``target_id``; returns the task UUID."""
        self._ensure_authenticated()
        xml = (
            "<create_task>"
            f"<name>{escape(name)}</name>"
            f'<config id="{escape(config_id)}"/>'
            f'<target id="{escape(target_id)}"/>'
            f'<scanner id="{DEFAULT_SCANNER_ID}"/>'
            "</create_task>"
        )
        root = self._request(xml)
        self._check_status(root, "create_task")
        task_id = root.findtext("id")
        if not task_id:
            raise GreenboneError("create_task response contained no task id")
        return task_id

    def start_task(self, task_id: str) -> str | None:
        """Start a task; returns the report UUID when the engine gives one."""
        self._ensure_authenticated()
        root = self._request(f'<start_task task_id="{escape(task_id)}"/>')
        self._check_status(root, "start_task")
        return root.findtext("report_id")

    def get_task_status(self, task_id: str) -> dict:
        """Return ``{"status": ..., "progress": ..., "report_id": ...}``."""
        self._ensure_authenticated()
        root = self._request(f'<get_tasks task_id="{escape(task_id)}"/>')
        self._check_status(root, "get_tasks")
        task = root.find("task")
        if task is None:
            raise GreenboneError(f"get_tasks response contained no task {task_id}")
        report_el = task.find("last_report/report")
        return {
            "status": task.findtext("status") or "Unknown",
            "progress": task.findtext("progress") or "",
            "report_id": report_el.get("id") if report_el is not None else None,
        }

    def get_report(self, report_id: str) -> list[dict]:
        """Fetch a report and normalise its results.

        Each result is ``{host, cve_id?, plugin_name?, plugin_output?,
        severity}`` — the same shape the correlation path consumes.
        """
        self._ensure_authenticated()
        root = self._request(f'<get_reports report_id="{escape(report_id)}" details="1"/>')
        self._check_status(root, "get_reports")
        results: list[dict] = []
        for result in root.iter("result"):
            host = (result.findtext("host") or "").strip() or None
            nvt = result.find("nvt")
            plugin_name = None
            cve_id = None
            if nvt is not None:
                plugin_name = (nvt.findtext("name") or "").strip() or None
                raw_cve = (nvt.findtext("cve") or "").strip()
                # GMP may list "NOCVE" or several comma-separated CVEs;
                # keep the first real CVE id.
                for candidate in raw_cve.split(","):
                    candidate = candidate.strip().upper()
                    if candidate.startswith("CVE-"):
                        cve_id = candidate
                        break
            severity_text = (result.findtext("severity") or "").strip()
            try:
                severity = severity_from_score(float(severity_text)) if severity_text else "medium"
            except ValueError:
                severity = "medium"
            results.append(
                {
                    "host": host,
                    "cve_id": cve_id,
                    "plugin_name": plugin_name,
                    "plugin_output": (result.findtext("description") or "").strip() or None,
                    "severity": severity,
                }
            )
        return results
