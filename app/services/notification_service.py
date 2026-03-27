from __future__ import annotations

import logging
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
    # Placeholder transport. Wire SMTP/provider here without changing auth logic.
    link_or_token = build_password_reset_link(token)
    logger.info("Password reset requested for %s with payload: %s", email, link_or_token)