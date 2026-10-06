from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Iterator

from app.config import DATA_DIR, DB_PATH, HK, IMAGE_DIR, MAX_ATTEMPTS


def now_iso() -> str:
    return datetime.now(HK).isoformat(timespec="seconds")


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    IMAGE_DIR.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                password_hash TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TEXT NOT NULL,
                event_time TEXT,
                event_type TEXT,
                event_state TEXT,
                event_description TEXT,
                channel_id TEXT,
                channel_name TEXT,
                device_ip TEXT,
                source_ip TEXT,
                content_type TEXT,
                raw_body TEXT,
                image_path TEXT,
                queue_status TEXT NOT NULL DEFAULT 'queued',
                queue_attempts INTEGER NOT NULL DEFAULT 0,
                queue_error TEXT,
                next_attempt_at TEXT,
                sent_at TEXT,
                hidden INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_received ON events (received_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_queue ON events (queue_status, next_attempt_at)"
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(events)")}
        for name, kind in (("person_name", "TEXT"), ("open_method", "TEXT")):
            if name not in columns:
                conn.execute(f"ALTER TABLE events ADD COLUMN {name} {kind}")
        if "hidden" not in columns:
            conn.execute("ALTER TABLE events ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0")
        from app.hik import door_info, quiet_label

        pending = conn.execute(
            """
            SELECT id, event_type, raw_body, queue_status FROM events
            WHERE IFNULL(hidden, 0) = 0
              AND (
                lower(replace(IFNULL(event_type,''), '_', '')) = 'accesscontrollerevent'
                OR lower(replace(IFNULL(event_type,''), '_', '')) = 'heartbeat'
                OR IFNULL(open_method, '') != ''
                OR IFNULL(raw_body, '') LIKE '%AccessControllerEvent%'
                OR IFNULL(raw_body, '') LIKE '%heartBeat%'
              )
            """
        ).fetchall()
        for pending_row in pending:
            raw = pending_row["raw_body"] or ""
            quiet = quiet_label(pending_row["event_type"] or "", raw)
            if quiet:
                conn.execute(
                    """
                    UPDATE events
                    SET hidden = 1,
                        open_method = ?,
                        queue_status = CASE WHEN queue_status = 'queued' THEN 'kept' ELSE queue_status END,
                        next_attempt_at = CASE WHEN queue_status = 'queued' THEN NULL ELSE next_attempt_at END
                    WHERE id = ?
                    """,
                    (quiet, pending_row["id"]),
                )
                continue
            info = door_info(raw)
            conn.execute(
                "UPDATE events SET open_method = ?, person_name = ? WHERE id = ?",
                (info["open_method"], info["person_name"], pending_row["id"]),
            )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_key TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                ip TEXT,
                mac TEXT,
                last_seen TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


def admin_hash() -> str | None:
    with connect() as conn:
        row = conn.execute("SELECT password_hash FROM admin WHERE id = 1").fetchone()
    return row["password_hash"] if row else None


def set_admin_hash(password_hash: str) -> None:
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO admin (id, password_hash, updated_at)
            VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                password_hash = excluded.password_hash,
                updated_at = excluded.updated_at
            """,
            (password_hash, now_iso()),
        )


_VISIBLE = "IFNULL(hidden, 0) = 0"


def _filters(query: str, status: str) -> tuple[str, list[object]]:
    where: list[str] = []
    params: list[object] = []
    if not query:
        where.append(_VISIBLE)
    if status in {"queued", "sent", "failed"}:
        where.append("queue_status = ?")
        params.append(status)
    if query:
        pattern = _like(query)
        where.append(
            "("
            + " OR ".join(
                [
                    "IFNULL(event_type,'') LIKE ? ESCAPE '\\'",
                    "IFNULL(event_state,'') LIKE ? ESCAPE '\\'",
                    "IFNULL(event_description,'') LIKE ? ESCAPE '\\'",
                    "IFNULL(channel_id,'') LIKE ? ESCAPE '\\'",
                    "IFNULL(channel_name,'') LIKE ? ESCAPE '\\'",
                    "IFNULL(device_ip,'') LIKE ? ESCAPE '\\'",
                    "IFNULL(source_ip,'') LIKE ? ESCAPE '\\'",
                    "IFNULL(raw_body,'') LIKE ? ESCAPE '\\'",
                    "IFNULL(person_name,'') LIKE ? ESCAPE '\\'",
                    "IFNULL(open_method,'') LIKE ? ESCAPE '\\'",
                ]
            )
            + ")"
        )
        params.extend([pattern] * 10)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    return clause, params


def _like(query: str) -> str:
    escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def count_events(query: str, status: str) -> int:
    clause, params = _filters(query, status)
    with connect() as conn:
        row = conn.execute(f"SELECT COUNT(*) AS n FROM events{clause}", params).fetchone()
    return int(row["n"])


def list_events(query: str, status: str, page: int, page_size: int) -> list[dict]:
    clause, params = _filters(query, status)
    offset = (page - 1) * page_size
    with connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM events{clause} ORDER BY id DESC LIMIT ? OFFSET ?",
            [*params, page_size, offset],
        ).fetchall()
    return [dict(row) for row in rows]


def get_event(event_id: int) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    return dict(row) if row else None


def insert_event(
    *,
    event_time: str,
    event_type: str,
    event_state: str,
    event_description: str,
    channel_id: str,
    channel_name: str,
    device_ip: str,
    source_ip: str,
    content_type: str,
    raw_body: str,
    person_name: str = "",
    open_method: str = "",
    hidden: int = 0,
) -> int:
    received = now_iso()
    queued = not hidden
    with connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO events (
                received_at, event_time, event_type, event_state, event_description,
                channel_id, channel_name, device_ip, source_ip, content_type, raw_body,
                person_name, open_method, queue_status, next_attempt_at, hidden
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                received,
                event_time,
                event_type,
                event_state,
                event_description,
                channel_id,
                channel_name,
                device_ip,
                source_ip,
                content_type,
                raw_body,
                person_name,
                open_method,
                "queued" if queued else "kept",
                received if queued else None,
                1 if hidden else 0,
            ),
        )
        return int(cur.lastrowid)


def set_image(event_id: int, relative: str) -> None:
    with connect() as conn:
        conn.execute("UPDATE events SET image_path = ? WHERE id = ?", (relative, event_id))


def delete_event(event_id: int) -> tuple[bool, str | None]:
    with connect() as conn:
        row = conn.execute(
            "SELECT image_path FROM events WHERE id = ?", (event_id,)
        ).fetchone()
        if row is None:
            return False, None
        conn.execute("DELETE FROM events WHERE id = ?", (event_id,))
        return True, row["image_path"]


def clear_events() -> list[str]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT image_path FROM events WHERE image_path IS NOT NULL"
        ).fetchall()
        conn.execute("DELETE FROM events")
    return [row["image_path"] for row in rows if row["image_path"]]


def requeue_event(event_id: int) -> bool:
    with connect() as conn:
        cur = conn.execute(
            """
            UPDATE events
            SET queue_status = 'queued',
                queue_attempts = 0,
                queue_error = NULL,
                next_attempt_at = ?,
                sent_at = NULL
            WHERE id = ?
            """,
            (now_iso(), event_id),
        )
        return cur.rowcount > 0


def stats() -> dict[str, int]:
    day = datetime.now(HK).strftime("%Y-%m-%d")
    with connect() as conn:
        row = conn.execute(
            f"""
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(CASE WHEN received_at LIKE ? THEN 1 ELSE 0 END), 0) AS today,
                COALESCE(SUM(CASE WHEN queue_status = 'queued' THEN 1 ELSE 0 END), 0) AS queued,
                COALESCE(SUM(CASE WHEN queue_status = 'sent' THEN 1 ELSE 0 END), 0) AS sent,
                COALESCE(SUM(CASE WHEN queue_status = 'failed' THEN 1 ELSE 0 END), 0) AS failed
            FROM events
            WHERE {_VISIBLE}
            """,
            (day + "%",),
        ).fetchone()
    return {key: int(row[key]) for key in ("total", "today", "queued", "sent", "failed")}


def due_events(limit: int = 5) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            f"""
            SELECT * FROM events
            WHERE queue_status = 'queued'
              AND {_VISIBLE}
              AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
            ORDER BY id
            LIMIT ?
            """,
            (now_iso(), limit),
        ).fetchall()
    return [dict(row) for row in rows]


def latest_event_id(query: str = "") -> int:
    clause, params = _filters(query, "")
    with connect() as conn:
        row = conn.execute(
            f"SELECT MAX(id) AS n FROM events{clause}", params
        ).fetchone()
    return int(row["n"] or 0)


def upsert_device(device_key: str, name: str, ip: str, mac: str) -> None:
    stamp = now_iso()
    display = name or (f"裝置 {ip}" if ip else "未知裝置")
    with connect() as conn:
        if ip and device_key != f"ip:{ip}":
            conn.execute(
                "DELETE FROM devices WHERE device_key = ? AND device_key != ?",
                (f"ip:{ip}", device_key),
            )
        conn.execute(
            """
            INSERT INTO devices (device_key, name, ip, mac, last_seen, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_key) DO UPDATE SET
                name = CASE WHEN ? != '' THEN ? ELSE devices.name END,
                ip = CASE WHEN excluded.ip != '' THEN excluded.ip ELSE devices.ip END,
                mac = CASE WHEN excluded.mac != '' THEN excluded.mac ELSE devices.mac END,
                last_seen = excluded.last_seen
            """,
            (device_key, display, ip, mac, stamp, stamp, name, name),
        )


def list_devices() -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM devices ORDER BY last_seen DESC, id DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def get_device(device_id: int) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    return dict(row) if row else None


def delete_device(device_id: int) -> bool:
    with connect() as conn:
        cur = conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        return cur.rowcount > 0


def mark_sent(event_id: int) -> None:
    with connect() as conn:
        conn.execute(
            """
            UPDATE events
            SET queue_status = 'sent',
                sent_at = ?,
                queue_error = NULL,
                next_attempt_at = NULL
            WHERE id = ?
            """,
            (now_iso(), event_id),
        )


def mark_attempt(event_id: int, error: str) -> None:
    with connect() as conn:
        row = conn.execute(
            "SELECT queue_attempts FROM events WHERE id = ?", (event_id,)
        ).fetchone()
        if row is None:
            return
        attempts = int(row["queue_attempts"]) + 1
        message = error[:300]
        if attempts >= MAX_ATTEMPTS:
            conn.execute(
                """
                UPDATE events
                SET queue_attempts = ?,
                    queue_error = ?,
                    queue_status = 'failed',
                    next_attempt_at = NULL
                WHERE id = ?
                """,
                (attempts, message, event_id),
            )
            return
        delay = min(300, 10 * attempts)
        nxt = (datetime.now(HK) + timedelta(seconds=delay)).isoformat(timespec="seconds")
        conn.execute(
            """
            UPDATE events
            SET queue_attempts = ?,
                queue_error = ?,
                queue_status = 'queued',
                next_attempt_at = ?
            WHERE id = ?
            """,
            (attempts, message, nxt, event_id),
        )
