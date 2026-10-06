from __future__ import annotations

import os
from datetime import timedelta, timezone
from pathlib import Path

HK = timezone(timedelta(hours=8))
ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.environ.get("DATA_DIR", ROOT / "data"))
DB_PATH = DATA_DIR / "app.db"
SECRET_PATH = DATA_DIR / "secret.key"
PASSWORD_FILE = DATA_DIR / "initial-password.txt"
IMAGE_DIR = DATA_DIR / "images"
PAGE_SIZE = 20
MAX_BODY = 20 * 1024 * 1024
MAX_IMAGE = 8 * 1024 * 1024
MAX_ATTEMPTS = 8
PBKDF2_ROUNDS = 120_000
RAW_LIMIT = 500_000


def cloudflare_url() -> str:
    return os.environ.get("CLOUDFLARE_PUSH_URL", "").strip()


def cloudflare_token() -> str:
    return os.environ.get("CLOUDFLARE_PUSH_TOKEN", "").strip()
