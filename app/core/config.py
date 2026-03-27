from pathlib import Path
from urllib.parse import urlparse

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
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 30
    FRONTEND_RESET_PASSWORD_URL: str = ""
    DATABASE_URL: str = ""
    LOGSTASH_SHARED_SECRET: str = ""
    WORM_ENDPOINT: str = "http://minio:9000"
    WORM_BUCKET: str = "forensiq-cold-dev"
    WORM_ACCESS_KEY: str = "minioadmin"
    WORM_SECRET_KEY: str = "minioadmin"
    WORM_REGION: str = "us-east-1"
    WORM_VERIFY_SSL: bool = False
    WORM_RETENTION_DAYS: int = 7
    WORM_PROVIDER: str = "minio"
    SEALING_SIGNING_KEY_ID: str = "forensiq-local-key"
    SEALING_PRIVATE_KEY_PEM: str = ""
    LOGSTASH_CONFIG_VERSION: str = "v2.1.0"
    ES_URL: str = "https://es01:9200"
    ES_USER: str = "elastic"
    ES_PASSWORD: str = ""
    ES_CA_CERT_PATH: str = "/usr/share/logstash/config/certs/ca/ca.crt"
    OCSF_INDEX_PATTERN: str = "ocsf-logs-*"
    COLDSTACK_SIGNING_PRIVATE_KEY_B64: str = ""
    COLDSTACK_SIGNING_KEY_ID: str = "cold-stack-dev"
    COLDSTACK_TIMESTAMP_AUTHORITY: str = "backend-local"
    COLDSTACK_MAX_CLOCK_SKEW_MS: int = 500
    # ML / anomaly
    ANOMALY_MODEL_PATH: str = ""
    ANOMALY_WARMUP_THRESHOLD: int = 500
    RAG_RECOVERY_BATCH_SIZE: int = 1000
    # Normalization: business hours for after_hours (local UTC hour bounds)
    AFTER_HOURS_START_HOUR: int = 19
    AFTER_HOURS_END_HOUR: int = 7

    # Cold sealed JSON objects: same MinIO as WORM_* (endpoint/creds); separate bucket/prefix.
    MINIO_BUCKET: str = "cold-blocks"
    MINIO_PREFIX: str = "sealed-blocks"
    MINIO_RETENTION_MODE: str = "COMPLIANCE"
    MINIO_RETENTION_DAYS: int = 3650
    MINIO_AUTO_CREATE_BUCKET: bool = True

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
