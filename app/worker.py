from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request

from app.config import cloudflare_token, cloudflare_url
from app import db

log = logging.getLogger("hik.queue")


class _KeepStatus(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):  # type: ignore[no-untyped-def]
        return response

    https_response = http_response


def run_worker(stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            pump()
        except Exception:
            log.exception("推送隊列出錯")
        if stop.wait(5):
            return


def pump() -> None:
    url = cloudflare_url()
    if not url:
        return
    token = cloudflare_token()
    for row in db.due_events():
        try:
            _push(url, token, row)
        except Exception as exc:
            log.warning("事件 %s 推送失敗：%s", row["id"], exc)
            db.mark_attempt(row["id"], str(exc))
        else:
            db.mark_sent(row["id"])
            log.info("事件 %s 已推送", row["id"])


def _push(url: str, token: str, row: dict) -> None:
    payload = {
        "id": row["id"],
        "received_at": row["received_at"],
        "event_time": row["event_time"],
        "event_type": row["event_type"],
        "event_state": row["event_state"],
        "event_description": row["event_description"],
        "channel_id": row["channel_id"],
        "channel_name": row["channel_name"],
        "device_ip": row["device_ip"],
        "source_ip": row["source_ip"],
        "has_image": bool(row["image_path"]),
        "raw": (row["raw_body"] or "")[:100_000],
    }
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("Content-Type", "application/json; charset=utf-8")
    request.add_header("User-Agent", "hik-webhook/1.0")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    opener = urllib.request.build_opener(_KeepStatus)
    try:
        with opener.open(request, timeout=15) as response:
            status = getattr(response, "status", None) or response.getcode()
            if status >= 300:
                snippet = response.read(300).decode("utf-8", "replace")
                raise RuntimeError(f"HTTP {status} {snippet}".strip())
    except urllib.error.URLError as exc:
        raise RuntimeError(str(exc.reason if hasattr(exc, "reason") else exc)) from exc
