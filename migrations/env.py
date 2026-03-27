from logging.config import fileConfig
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import engine_from_config
from sqlalchemy import pool
from dotenv import load_dotenv

from alembic import context

# Ensure Alembic can import the application package when run from Docker/Task
# where CWD / entrypoint path may not include repo root on sys.path.
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.db.base import Base
from app.db import models  # noqa: F401

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Load the same env files used by runtime config.
load_dotenv(ROOT_DIR / "infrastructure" / "backend" / ".env", override=False)
load_dotenv(ROOT_DIR / ".env", override=False)

DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL:
    # Keep infrastructure/backend/.env Docker-friendly (host=db), but when Alembic
    # runs from the host machine, transparently swap db -> localhost.
    if not Path("/.dockerenv").exists():
        parts = urlsplit(DATABASE_URL)
        if parts.hostname == "db":
            host = "localhost"
            if parts.port is not None:
                host = f"{host}:{parts.port}"
            if parts.username:
                auth = parts.username
                if parts.password:
                    auth = f"{auth}:{parts.password}"
                netloc = f"{auth}@{host}"
            else:
                netloc = host
            DATABASE_URL = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    config.set_main_option("sqlalchemy.url", DATABASE_URL)

if not config.get_main_option("sqlalchemy.url"):
    raise RuntimeError(
        "DATABASE_URL is not set. Define it in environment or infrastructure/backend/.env."
    )

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in offline mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in online mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
