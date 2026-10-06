from __future__ import annotations

import hashlib
import secrets
import string
import threading
import time

from app.config import DATA_DIR, IMAGE_DIR, PASSWORD_FILE, PBKDF2_ROUNDS, SECRET_PATH
from app import db

_guard = threading.Lock()
_fails: dict[str, tuple[int, float]] = {}
LOCK_AFTER = 5
LOCK_SECONDS = 60

_LOWER = "abcdefghijkmnopqrstuvwxyz"
_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
_DIGITS = "23456789"
_SYMBOLS = "!@#$%^&*-_"


def generate_password() -> str:
    rng = secrets.SystemRandom()
    pool = _LOWER + _UPPER + _DIGITS + _SYMBOLS
    while True:
        chars = [
            rng.choice(_LOWER),
            rng.choice(_UPPER),
            rng.choice(_DIGITS),
            rng.choice(_SYMBOLS),
            *[rng.choice(pool) for _ in range(16)],
        ]
        rng.shuffle(chars)
        password = "".join(chars)
        if password[0] in string.ascii_letters + string.digits:
            return password


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds_text, salt_hex, hash_hex = stored.split("$")
        rounds = int(rounds_text)
        if algo != "pbkdf2_sha256" or rounds < 1 or rounds > 500_000:
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            rounds,
        )
        if len(digest.hex()) != len(hash_hex):
            return False
        return secrets.compare_digest(digest.hex(), hash_hex)
    except Exception:
        return False


def password_problem(password: str) -> str | None:
    if len(password) < 6:
        return "short"
    if len(password) > 128:
        return "long"
    return None


def too_many(ip: str) -> bool:
    now = time.time()
    with _guard:
        count, locked_until = _fails.get(ip, (0, 0.0))
        if locked_until and now < locked_until and count >= LOCK_AFTER:
            return True
        if locked_until and now >= locked_until:
            _fails.pop(ip, None)
        return False


def record_fail(ip: str) -> None:
    now = time.time()
    with _guard:
        count, locked_until = _fails.get(ip, (0, 0.0))
        if locked_until and now >= locked_until:
            count = 0
            locked_until = 0.0
        count += 1
        if count >= LOCK_AFTER:
            locked_until = now + LOCK_SECONDS
        _fails[ip] = (count, locked_until)


def record_ok(ip: str) -> None:
    with _guard:
        _fails.pop(ip, None)


def load_secret() -> str:
    return SECRET_PATH.read_text(encoding="utf-8").strip()


def discard_initial_password_file() -> None:
    PASSWORD_FILE.unlink(missing_ok=True)


def bootstrap() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    IMAGE_DIR.mkdir(parents=True, exist_ok=True)
    if not SECRET_PATH.exists() or not SECRET_PATH.read_text(encoding="utf-8").strip():
        SECRET_PATH.write_text(secrets.token_hex(32), encoding="utf-8")
    db.init()
    if db.admin_hash():
        return
    password = generate_password()
    db.set_admin_hash(hash_password(password))
    PASSWORD_FILE.write_text(
        password
        + "\n\n這是首次啟動產生的登入密碼。檔案第一行就是密碼。\n"
        + "登入網頁後可以更改。更改後這個檔案會刪除。\n",
        encoding="utf-8",
    )
    line = "=" * 46
    print(
        f"\n{line}\n首次登入密碼\n{password}\n"
        f"容器內：{PASSWORD_FILE}\n"
        f"主機上：data/initial-password.txt\n{line}\n",
        flush=True,
    )
