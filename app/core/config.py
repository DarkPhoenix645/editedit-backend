from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    PROJECT_NAME: str = "editedit-backend"
    SECRET_KEY: str = ""
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
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

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()