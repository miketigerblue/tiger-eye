from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings

# Single source of truth for vector dimensions — referenced by ORM model,
# migration DDL, and embedding generation.
EMBEDDING_DIMENSIONS = 1536


class Settings(BaseSettings):
    """tiger-eye configuration. All values from environment / .env file."""

    # Database — points at tiger2go Postgres by default
    database_url: str = "postgresql+asyncpg://user:pass@localhost:5432/tiger2go"

    # OpenAI
    openai_api_key: str = ""

    @model_validator(mode="after")
    def _require_openai_key(self):
        if not self.openai_api_key:
            raise ValueError("OPENAI_API_KEY is required — set it in .env or environment")
        return self

    # Embedding
    embedding_model: str = "text-embedding-3-small"
    embedding_dimensions: int = EMBEDDING_DIMENSIONS

    # Enrichment loop
    enrich_interval: int = 60  # seconds between poll cycles
    enrich_batch_size: int = 20  # entries per cycle

    # Internal API
    api_host: str = "0.0.0.0"  # nosec B104 — container bind
    api_port: int = 8080

    # Logging
    log_level: str = "INFO"
    log_json: bool = True  # False for human-readable dev output

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache
def get_settings() -> Settings:
    """Lazy singleton — settings are created on first access, not at import time."""
    return Settings()
