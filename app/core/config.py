from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent

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
    COLDSTACK_MINIO_ENDPOINT: str = "minio:9000"
    COLDSTACK_MINIO_ACCESS_KEY: str = "minioadmin"
    COLDSTACK_MINIO_SECRET_KEY: str = "minioadmin"
    COLDSTACK_MINIO_SECURE: bool = False
    COLDSTACK_MINIO_BUCKET: str = "cold-blocks"
    COLDSTACK_MINIO_PREFIX: str = "sealed-blocks"
    COLDSTACK_MINIO_RETENTION_MODE: str = "COMPLIANCE"
    COLDSTACK_MINIO_RETENTION_DAYS: int = 3650
    COLDSTACK_MINIO_AUTO_CREATE_BUCKET: bool = True

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()