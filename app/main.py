from __future__ import annotations

import logging
import math
import secrets
import threading
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app import db
from app.auth import (
    bootstrap,
    discard_initial_password_file,
    hash_password,
    load_secret,
    password_problem,
    record_fail,
    record_ok,
    too_many,
    verify_password,
)
from app.config import (
    DATA_DIR,
    HEARTBEAT_STALE_SECONDS,
    HK,
    IMAGE_DIR,
    MAX_BODY,
    MAX_IMAGE,
    PAGE_SIZE,
    cloudflare_url,
)
from app.hik import (
    clock_text,
    day_text,
    door_info,
    full_text,
    heartbeat_device,
    is_heartbeat_signal,
    parse_dt,
    parse_payload,
    quiet_label,
    state_label,
    type_label,
    weekday_text,
)
from app.worker import run_worker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("hik")

bootstrap()

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

FLASH = {
    "saved": "密碼已更新。之後請用新密碼登入。",
    "short": "新密碼至少要 6 個字元。",
    "long": "新密碼不可長過 128 個字元。",
    "mismatch": "兩次新密碼不一致。",
    "wrong": "現有密碼不正確。",
    "deleted": "已刪除事件。",
    "cleared": "已清除全部事件。",
    "requeued": "已重新排隊。",
    "csrf": "頁面已過期，請再試一次。",
    "missing": "找不到這個事件。",
    "removed": "已移除沒有連線的裝置。",
    "online": "這部裝置仍有心跳，不能移除。",
}
BAD_FLASH = {"short", "long", "mismatch", "wrong", "csrf", "missing", "online"}
LOGIN_ERRORS = {
    "bad": "密碼不正確。",
    "locked": "嘗試次數太多，請約 1 分鐘後再試。",
}
QUEUE_LABELS = {
    "queued": "排隊中",
    "sent": "已推送",
    "failed": "推送失敗",
    "kept": "已收錄",
}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ready = "已設定" if cloudflare_url() else "未設定，事件只會排隊"
    log.info("Cloudflare 推送：%s", ready)
    stop = threading.Event()
    thread = threading.Thread(target=run_worker, args=(stop,), name="cloudflare-queue", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=2)


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=load_secret(),
    session_cookie="hik_session",
    max_age=60 * 60 * 12,
    same_site="lax",
    https_only=False,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    content_type = response.headers.get("content-type", "")
    if content_type.startswith("text/html"):
        response.headers["Cache-Control"] = "no-store"
    return response


def client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def guard(request: Request) -> RedirectResponse | None:
    if request.session.get("auth"):
        return None
    return RedirectResponse("/", status_code=303)


def csrf_ok(request: Request, token: str) -> bool:
    expected = request.session.get("csrf") or ""
    if not expected or not token or len(expected) != len(token):
        return False
    from secrets import compare_digest

    return compare_digest(expected, token)


async def form_values(request: Request) -> dict[str, str]:
    raw = await request.body()
    if len(raw) > 100_000:
        return {}
    parsed = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
    return {key: values[0] for key, values in parsed.items() if values}


def take_flash(request: Request) -> tuple[str | None, bool]:
    code = request.query_params.get("m", "")
    return FLASH.get(code), code in BAD_FLASH


def view_event(row: dict) -> dict:
    received = parse_dt(row.get("received_at"))
    happened_raw = row.get("event_time") or ""
    happened = parse_dt(happened_raw)
    sent = parse_dt(row.get("sent_at") or "")
    status = row.get("queue_status") or "queued"
    code = row.get("event_type") or ""
    raw = row.get("raw_body") or ""
    access = door_info(raw)
    quiet = quiet_label(code, raw)
    label = access["open_method"] or quiet or type_label(code)
    return {
        "id": row["id"],
        "clock": clock_text(received),
        "weekday": weekday_text(received),
        "day": day_text(received),
        "received": full_text(received),
        "happened": full_text(happened) if happened else happened_raw,
        "type_label": label,
        "failed_face": label == "人臉認證失敗",
        "type_code": "" if access["open_method"] or quiet else code,
        "open_method": access["open_method"] or quiet,
        "person_name": access["person_name"],
        "employee_no": access["employee_no"],
        "door_no": access["door_no"],
        "card_no": access["card_no"],
        "device_name": access["device_name"],
        "state_label": state_label(row.get("event_state") or ""),
        "description": row.get("event_description") or "",
        "channel_id": row.get("channel_id") or "",
        "channel_name": row.get("channel_name") or "",
        "device_ip": row.get("device_ip") or "",
        "source_ip": row.get("source_ip") or "",
        "content_type": row.get("content_type") or "",
        "raw_body": row.get("raw_body") or "",
        "has_image": bool(row.get("image_path")),
        "queue_status": status,
        "queue_label": QUEUE_LABELS.get(status, status),
        "queue_attempts": row.get("queue_attempts") or 0,
        "queue_error": row.get("queue_error") or "",
        "sent": full_text(sent),
    }


def remove_image(relative: str | None) -> None:
    if not relative:
        return
    root = IMAGE_DIR.resolve()
    path = (DATA_DIR / relative).resolve()
    if path.is_relative_to(root) and path.is_file():
        path.unlink()


def safe_image(relative: str | None) -> Path | None:
    if not relative:
        return None
    root = IMAGE_DIR.resolve()
    path = (DATA_DIR / relative).resolve()
    if path.is_relative_to(root) and path.is_file():
        return path
    return None


def page_context(request: Request, **extra: object) -> dict:
    flash, flash_bad = take_flash(request)
    context = {
        "request": request,
        "authed": bool(request.session.get("auth")),
        "csrf": request.session.get("csrf", ""),
        "flash": flash,
        "flash_bad": flash_bad,
        "cloudflare_ready": bool(cloudflare_url()),
    }
    context.update(extra)
    return context


def render(request: Request, name: str, status_code: int = 200, **extra: object):
    return templates.TemplateResponse(
        request,
        name,
        page_context(request, **extra),
        status_code=status_code,
    )


@app.get("/health")
def health() -> dict[str, bool]:
    return {"ok": True}


@app.api_route("/webhook", methods=["GET", "POST", "PUT", "HEAD"])
async def webhook(request: Request):
    if request.method in {"GET", "HEAD"}:
        return PlainTextResponse("ok")
    length = request.headers.get("content-length", "")
    if length.isdigit() and int(length) > MAX_BODY:
        return PlainTextResponse("too large", status_code=413)
    body = await request.body()
    if len(body) > MAX_BODY:
        return PlainTextResponse("too large", status_code=413)
    if not body.strip(b" \r\n\t"):
        return PlainTextResponse("ok")

    content_type = request.headers.get("content-type", "")
    parsed = parse_payload(content_type, body)
    quiet = quiet_label(parsed.event_type, parsed.raw_text)
    if is_heartbeat_signal(parsed.event_type, parsed.raw_text):
        device = heartbeat_device(parsed.raw_text, client_ip(request))
        if device:
            try:
                db.upsert_device(
                    device["device_key"],
                    device["name"],
                    device["ip"],
                    device["mac"],
                )
            except Exception:
                log.exception("記錄心跳失敗")
                return PlainTextResponse("error", status_code=500)
            log.info("心跳 %s %s", device["name"] or device["ip"], device["ip"])
    access = door_info(parsed.raw_text)
    try:
        event_id = db.insert_event(
            event_time=parsed.event_time,
            event_type=parsed.event_type,
            event_state=parsed.event_state,
            event_description=parsed.event_description,
            channel_id=parsed.channel_id,
            channel_name=parsed.channel_name,
            device_ip=parsed.device_ip,
            source_ip=client_ip(request)[:80],
            content_type=content_type[:200],
            raw_body=parsed.raw_text,
            person_name=access["person_name"],
            open_method=quiet or access["open_method"],
            hidden=1 if quiet else 0,
        )
        if parsed.images:
            ext, blob = parsed.images[0]
            if len(blob) <= MAX_IMAGE:
                name = f"{event_id}.{ext}"
                (IMAGE_DIR / name).write_bytes(blob)
                db.set_image(event_id, f"images/{name}")
            else:
                log.info("事件 %s 圖片過大，已略過", event_id)
    except Exception:
        log.exception("儲存 webhook 失敗")
        return PlainTextResponse("error", status_code=500)

    log.info(
        "收到事件 %s type=%s channel=%s from=%s",
        event_id,
        quiet or access["open_method"] or parsed.event_type or "-",
        parsed.channel_id or "-",
        client_ip(request),
    )
    return PlainTextResponse("ok")


@app.api_route("/", methods=["POST", "PUT"])
async def root_webhook(request: Request):
    return await webhook(request)


@app.get("/")
def home(request: Request):
    if request.session.get("auth"):
        return RedirectResponse("/events", status_code=303)
    error = LOGIN_ERRORS.get(request.query_params.get("e", ""))
    return render(request, "login.html", error=error)


@app.post("/login")
async def login(request: Request):
    ip = client_ip(request)
    if too_many(ip):
        return RedirectResponse("/?e=locked", status_code=303)
    form = await form_values(request)
    password = form.get("password", "").strip()
    stored = db.admin_hash()
    if not stored or len(password) > 128 or not verify_password(password, stored):
        record_fail(ip)
        return RedirectResponse("/?e=bad", status_code=303)
    record_ok(ip)
    request.session.clear()
    request.session["auth"] = True
    request.session["csrf"] = secrets.token_urlsafe(32)
    return RedirectResponse("/events", status_code=303)


@app.post("/logout")
async def logout(request: Request):
    form = await form_values(request)
    if request.session.get("auth") and not csrf_ok(request, form.get("csrf", "")):
        return RedirectResponse("/events?m=csrf", status_code=303)
    request.session.clear()
    return RedirectResponse("/", status_code=303)


def device_online(last_seen: str) -> bool:
    last = parse_dt(last_seen)
    if last is None:
        return False
    return (datetime.now(HK) - last).total_seconds() <= HEARTBEAT_STALE_SECONDS


def view_devices() -> list[dict]:
    items = []
    for row in db.list_devices():
        online = device_online(row.get("last_seen") or "")
        last = parse_dt(row.get("last_seen") or "")
        day = day_text(last)
        clock = clock_text(last) if last else ""
        today = datetime.now(HK).strftime("%Y-%m-%d")
        when = clock if not day or day == today else f"{day} {clock}"
        items.append(
            {
                "id": row["id"],
                "name": row.get("name") or row.get("ip") or "未知裝置",
                "ip": row.get("ip") or "",
                "mac": row.get("mac") or "",
                "last_seen": full_text(last),
                "last_clock": when,
                "online": online,
                "status_label": "已連線" if online else "沒有連線",
            }
        )
    items.sort(key=lambda item: (not item["online"], item["name"]))
    return items


def event_list_args(request: Request) -> dict:
    query = request.query_params.get("q", "").strip()[:100]
    status = request.query_params.get("status", "")
    if status not in {"queued", "sent", "failed"}:
        status = ""
    try:
        page = int(request.query_params.get("page", "1"))
    except ValueError:
        page = 1
    page = max(1, page)
    total = db.count_events(query, status)
    pages = max(1, math.ceil(total / PAGE_SIZE)) if total else 1
    if page > pages:
        page = pages
    rows = [view_event(row) for row in db.list_events(query, status, page, PAGE_SIZE)]
    numbers = db.stats()
    if numbers["total"] == 0:
        empty = "none"
    elif total == 0:
        empty = "filter"
    else:
        empty = ""
    return {
        "events": rows,
        "stats": numbers,
        "total": total,
        "page": page,
        "pages": pages,
        "q": query,
        "status": status,
        "empty": empty,
    }


@app.get("/live")
def live(request: Request):
    if not request.session.get("auth"):
        return JSONResponse({"ok": False}, status_code=401)
    numbers = db.stats()
    return JSONResponse(
        {
            "ok": True,
            "devices": view_devices(),
            "stats": numbers,
            "latest_id": db.latest_event_id(request.query_params.get("q", "").strip()[:100]),
            "stale_seconds": HEARTBEAT_STALE_SECONDS,
        }
    )


@app.get("/events")
def events(request: Request):
    denied = guard(request)
    if denied:
        return denied
    return render(
        request,
        "events.html",
        **event_list_args(request),
        devices=view_devices(),
        latest_id=db.latest_event_id(request.query_params.get("q", "").strip()[:100]),
        stale_seconds=HEARTBEAT_STALE_SECONDS,
        webhook_url=str(request.base_url).rstrip("/") + "/",
    )


@app.get("/events/feed")
def events_feed(request: Request):
    denied = guard(request)
    if denied:
        return denied
    return render(request, "events_feed.html", **event_list_args(request))


@app.post("/devices/{device_id}/remove")
async def device_remove(request: Request, device_id: int):
    denied = guard(request)
    if denied:
        return denied
    form = await form_values(request)
    if not csrf_ok(request, form.get("csrf", "")):
        return RedirectResponse("/events?m=csrf", status_code=303)
    row = db.get_device(device_id)
    if row is None:
        return RedirectResponse("/events", status_code=303)
    if device_online(row.get("last_seen") or ""):
        return RedirectResponse("/events?m=online", status_code=303)
    db.delete_device(device_id)
    return RedirectResponse("/events?m=removed", status_code=303)


@app.get("/events/{event_id}")
def event_detail(request: Request, event_id: int):
    denied = guard(request)
    if denied:
        return denied
    row = db.get_event(event_id)
    if row is None:
        return RedirectResponse("/events?m=missing", status_code=303)
    return render(request, "detail.html", event=view_event(row))


@app.get("/events/{event_id}/image")
def event_image(request: Request, event_id: int):
    denied = guard(request)
    if denied:
        return denied
    row = db.get_event(event_id)
    path = safe_image(row.get("image_path") if row else None)
    if path is None:
        raise HTTPException(status_code=404)
    media = "image/png" if path.suffix.lower() == ".png" else "image/jpeg"
    return FileResponse(path, media_type=media)


@app.post("/events/{event_id}/delete")
async def event_delete(request: Request, event_id: int):
    denied = guard(request)
    if denied:
        return denied
    form = await form_values(request)
    if not csrf_ok(request, form.get("csrf", "")):
        return RedirectResponse("/events?m=csrf", status_code=303)
    found, image = db.delete_event(event_id)
    if found:
        remove_image(image)
        return RedirectResponse("/events?m=deleted", status_code=303)
    return RedirectResponse("/events?m=missing", status_code=303)


@app.post("/events/{event_id}/requeue")
async def event_requeue(request: Request, event_id: int):
    denied = guard(request)
    if denied:
        return denied
    form = await form_values(request)
    if not csrf_ok(request, form.get("csrf", "")):
        return RedirectResponse(f"/events/{event_id}?m=csrf", status_code=303)
    if not db.requeue_event(event_id):
        return RedirectResponse("/events?m=missing", status_code=303)
    return RedirectResponse(f"/events/{event_id}?m=requeued", status_code=303)


@app.post("/events/clear")
async def events_clear(request: Request):
    denied = guard(request)
    if denied:
        return denied
    form = await form_values(request)
    if not csrf_ok(request, form.get("csrf", "")):
        return RedirectResponse("/events?m=csrf", status_code=303)
    for image in db.clear_events():
        remove_image(image)
    return RedirectResponse("/events?m=cleared", status_code=303)


def format_bytes(size: int) -> str:
    value = float(max(0, size))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{int(size)} B"


@app.get("/manage")
def manage(request: Request):
    denied = guard(request)
    if denied:
        return denied
    report = db.storage_report()
    storage = {key: format_bytes(value) for key, value in report.items()}
    return render(request, "password.html", storage=storage)


@app.get("/password")
def password_form(request: Request):
    target = "/manage"
    if request.url.query:
        target = f"/manage?{request.url.query}"
    return RedirectResponse(target, status_code=303)


@app.post("/password")
async def password_change(request: Request):
    denied = guard(request)
    if denied:
        return denied
    form = await form_values(request)
    if not csrf_ok(request, form.get("csrf", "")):
        return RedirectResponse("/manage?m=csrf", status_code=303)
    current = form.get("current", "").strip()
    new = form.get("new", "").strip()
    again = form.get("again", "").strip()
    stored = db.admin_hash()
    if not stored or len(current) > 128 or not verify_password(current, stored):
        return RedirectResponse("/manage?m=wrong", status_code=303)
    if new != again:
        return RedirectResponse("/manage?m=mismatch", status_code=303)
    problem = password_problem(new)
    if problem:
        return RedirectResponse(f"/manage?m={problem}", status_code=303)
    db.set_admin_hash(hash_password(new))
    discard_initial_password_file()
    return RedirectResponse("/manage?m=saved", status_code=303)


@app.exception_handler(404)
async def not_found(request: Request, _exc: Exception):
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        if not request.session.get("auth"):
            return RedirectResponse("/", status_code=303)
        return render(request, "missing.html", status_code=404)
    return PlainTextResponse("not found", status_code=404)


app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
