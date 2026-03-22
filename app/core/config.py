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
    COLDSTACK_STORAGE_URI_PREFIX: str = "postgresql://cold_stored_blocks"
    COLDSTACK_TIMESTAMP_AUTHORITY: str = "backend-local"
    COLDSTACK_MAX_CLOCK_SKEW_MS: int = 500

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()