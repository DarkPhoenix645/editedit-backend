from pathlib import Path
from urllib.parse import urlparse

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


def _normalize_minio_endpoint(v: object) -> str:
    if v is None or v == "":
        return "minio:9000"
    if not isinstance(v, str):
        return str(v)
    s = v.strip()
    if "://" not in s:
        return s
    p = urlparse(s)
    host = p.hostname
    if not host:
        return "minio:9000"
    if p.port is not None:
        return f"{host}:{p.port}"
    if p.scheme == "https":
        return f"{host}:443"
    return f"{host}:80"


class Settings(BaseSettings):
    PROJECT_NAME: str = "editedit-backend"
    SECRET_KEY: str = ""
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    DATABASE_URL: str = ""
    COLDSTACK_SIGNING_PRIVATE_KEY_B64: str = ""
    COLDSTACK_SIGNING_KEY_ID: str = "cold-stack-dev"
    COLDSTACK_TIMESTAMP_AUTHORITY: str = "backend-local"
    COLDSTACK_MAX_CLOCK_SKEW_MS: int = 500

    MINIO_ENDPOINT: str = "minio:9000"
    MINIO_ACCESS_KEY: str = "minioadmin"
    MINIO_SECRET_KEY: str = "minioadmin"
    MINIO_SECURE: bool = False
    MINIO_BUCKET: str = "cold-blocks"
    MINIO_PREFIX: str = "sealed-blocks"
    MINIO_RETENTION_MODE: str = "COMPLIANCE"
    MINIO_RETENTION_DAYS: int = 3650
    MINIO_AUTO_CREATE_BUCKET: bool = True

    @field_validator("MINIO_ENDPOINT", mode="before")
    @classmethod
    def _endpoint_host_port(cls, v: object) -> str:
        return _normalize_minio_endpoint(v)

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
