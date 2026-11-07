import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")


@dataclass(frozen=True)
class Settings:
    supabase_url: str
    supabase_secret_key: str
    r2_account_id: str
    r2_access_key_id: str
    r2_secret_access_key: str
    r2_bucket: str


def load_settings() -> Settings:
    names = {
        "supabase_url": "SUPABASE_URL",
        "supabase_secret_key": "SUPABASE_SECRET_KEY",
        "r2_account_id": "R2_ACCOUNT_ID",
        "r2_access_key_id": "R2_ACCESS_KEY_ID",
        "r2_secret_access_key": "R2_SECRET_ACCESS_KEY",
        "r2_bucket": "R2_BUCKET",
    }
    values = {field: os.environ.get(env, "").strip() for field, env in names.items()}
    missing = [names[f] for f, v in values.items() if not v]
    if missing:
        raise SystemExit(f"Missing in back-zurag/.env: {', '.join(missing)} (see .env.example)")
    return Settings(**values)
