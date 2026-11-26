"""Email service.

Development behaviour: emails are logged, never sent. Production wires a
real provider (SES/SMTP) behind the same interface. Invitation and
password-reset emails contain a one-time link; the token itself is never
logged.
"""

from __future__ import annotations

import logging
import smtplib

from app.config import get_settings

logger = logging.getLogger("null.email")


def send_reply_email(to: str, subject: str, body: str) -> bool:
    """Send a ticket reply. Returns True when it went out over SMTP.

    When no SMTP host is configured this falls back to the dev behaviour
    (logged, never sent) and returns False — the caller still records
    the outbound message row either way.
    """
    settings = get_settings()
    if not settings.smtp_host:
        send_email(to, subject, body)
        return False
    message = f"From: {settings.email_from}\r\nTo: {to}\r\nSubject: {subject}\r\n\r\n{body}"
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30) as smtp:
            smtp.ehlo()
            try:
                smtp.starttls()
                smtp.ehlo()
            except smtplib.SMTPException:
                pass  # server does not offer STARTTLS; continue plain
            if settings.smtp_user:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.sendmail(settings.email_from, [to], message)
    except (smtplib.SMTPException, OSError) as exc:
        logger.warning("SMTP reply to %s failed: %s", to, exc)
        return False
    logger.info("EMAIL (smtp) to=%s subject=%s", to, subject)
    return True


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
