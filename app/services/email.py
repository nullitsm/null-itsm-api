"""Email service.

Development behaviour: emails are logged, never sent. Production wires a
real provider (SES/SMTP) behind the same interface. Invitation and
password-reset emails contain a one-time link; the token itself is never
logged.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("null.email")


def send_email(to: str, subject: str, body: str) -> None:
    """Send (dev: log) an email. The body must not contain raw tokens."""
    logger.info("EMAIL to=%s subject=%s\n%s", to, subject, body)


def send_invitation_email(to: str, org_name: str, accept_url: str) -> None:
    send_email(
        to,
        f"You are invited to join {org_name} on NULL ITSM",
        f"You have been invited to join {org_name}.\n"
        f"Accept your invitation here: {accept_url}\n"
        "This invitation expires in 7 days.",
    )


def send_password_reset_email(to: str, reset_url: str) -> None:
    send_email(
        to,
        "Reset your NULL ITSM password",
        "You requested a password reset.\n"
        f"Reset your password here: {reset_url}\n"
        "This link expires in 60 minutes. If you did not request this, ignore this email.",
    )
