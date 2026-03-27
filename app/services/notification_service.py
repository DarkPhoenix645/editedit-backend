from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from urllib.parse import quote_plus

from app.core.config import settings

logger = logging.getLogger(__name__)


def build_password_reset_link(token: str) -> str:
    base = settings.FRONTEND_RESET_PASSWORD_URL.strip()
    if not base:
        return token
    separator = "&" if "?" in base else "?"
    return f"{base}{separator}token={quote_plus(token)}"


def send_password_reset_email(*, email: str, token: str) -> None:
    link_or_token = build_password_reset_link(token)
    if not settings.SMTP_HOST.strip():
        logger.info(
            "Password reset for %s (SMTP_HOST unset; set SMTP_* to send mail): %s",
            email,
            link_or_token,
        )
        return

    msg = EmailMessage()
    msg["Subject"] = "Password reset"
    from_addr = settings.SMTP_FROM.strip() or settings.SMTP_USER
    if not from_addr:
        logger.warning("SMTP_FROM and SMTP_USER are empty; cannot send password reset email")
        logger.info("Password reset for %s: %s", email, link_or_token)
        return
    msg["From"] = from_addr
    msg["To"] = email
    msg.set_content(
        "You requested a password reset.\n\n"
        f"Use this link (or token) to set a new password:\n\n{link_or_token}\n"
    )

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=30) as smtp:
            if settings.SMTP_USE_TLS:
                smtp.starttls()
            if settings.SMTP_USER:
                smtp.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            smtp.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        # Do not fail the forgot-password response (still 202); token was issued and audit runs upstream.
        logger.exception("SMTP send failed for password reset to %s: %s", email, exc)
