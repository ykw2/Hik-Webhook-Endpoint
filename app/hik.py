from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime

from app.config import HK, RAW_LIMIT

TYPE_LABELS = {
    "vmd": "移動偵測",
    "motion": "移動偵測",
    "linedetection": "越線偵測",
    "fielddetection": "區域入侵",
    "regionentrance": "進入區域",
    "regionexiting": "離開區域",
    "loitering": "徘徊",
    "group": "人群聚集",
    "rapidmove": "快速移動",
    "parking": "停車",
    "unattendedbaggage": "物品遺留",
    "attendedbaggage": "物品拿取",
    "audioexception": "音訊異常",
    "audiodetection": "音訊異常",
    "scenechangedetection": "場景變更",
    "facedetection": "人臉偵測",
    "facecapture": "人臉擷取",
    "anpr": "車牌識別",
    "anpralarm": "車牌識別",
    "vehicledetection": "車輛偵測",
    "mixedtargetdetection": "目標偵測",
    "videoloss": "影像遺失",
    "shelteralarm": "鏡頭遮擋",
    "tamperdetection": "遮擋偵測",
    "defocus": "失焦",
    "pir": "被動紅外",
    "io": "警報輸入",
    "alarmin": "警報輸入",
    "diskfull": "磁碟已滿",
    "diskerror": "磁碟錯誤",
    "illaccess": "非法登入",
    "ipconflict": "IP 衝突",
    "nicbroken": "網絡中斷",
    "tma": "溫度警報",
    "tmpa": "溫度預警",
    "temperature": "溫度",
    "firedetection": "火警",
    "smokedetection": "煙霧",
    "falldown": "跌倒",
    "advreachheight": "攀高",
    "accesscontrollerevent": "門禁",
    "heartbeat": "心跳",
    "videomismatch": "影像不符",
    "badvideo": "影像異常",
}

STATE_LABELS = {
    "active": "觸發",
    "inactive": "恢復",
    "pulse": "脈衝",
}


@dataclass
class ParsedEvent:
    event_type: str = ""
    event_state: str = ""
    event_time: str = ""
    event_description: str = ""
    channel_id: str = ""
    channel_name: str = ""
    device_ip: str = ""
    raw_text: str = ""
    images: list[tuple[str, bytes]] = field(default_factory=list)


def type_label(code: str) -> str:
    if not code:
        return "未識別事件"
    return TYPE_LABELS.get(code.lower(), code)


def state_label(state: str) -> str:
    if not state:
        return ""
    return STATE_LABELS.get(state.lower(), state)


def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    if not text:
        return None
    if re.fullmatch(r"\d{14}", text):
        try:
            return datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=HK)
        except ValueError:
            return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=HK)
    return parsed.astimezone(HK)


def clock_text(value: datetime | None) -> str:
    return value.strftime("%H:%M:%S") if value else "--:--:--"


def day_text(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d") if value else ""


def full_text(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else ""


def parse_payload(content_type: str, body: bytes) -> ParsedEvent:
    text = ""
    images: list[tuple[str, bytes]] = []
    if content_type.lower().startswith("multipart/"):
        for _headers, data in _split_multipart(content_type, body):
            image = _image_ext(data)
            if image:
                images.append((image, data))
                continue
            part_text = _decode(data).strip()
            if not part_text:
                continue
            if part_text.startswith("<") or part_text.startswith("{") or part_text.startswith("["):
                text = part_text
            elif not text:
                text = part_text
    else:
        image = _image_ext(body)
        if image:
            images.append((image, body))
        else:
            text = _decode(body)

    if len(text) > RAW_LIMIT:
        text = text[:RAW_LIMIT] + "\n\n…（內容已截斷）"

    fields = _fields_from_text(text)
    return ParsedEvent(
        event_type=_clip(_pick(fields, "eventType", "event_type"), 120),
        event_state=_clip(_pick(fields, "eventState", "event_state"), 40),
        event_time=_clip(_pick(fields, "dateTime", "date_time", "time"), 80),
        event_description=_clip(
            _pick(fields, "eventDescription", "event_description", "description"), 500
        ),
        channel_id=_clip(
            _pick(fields, "channelID", "channelId", "dynChannelID", "channel"), 120
        ),
        channel_name=_clip(_pick(fields, "channelName", "cameraName", "channel_name"), 120),
        device_ip=_clip(_pick(fields, "ipAddress", "ip", "deviceIP"), 80),
        raw_text=text,
        images=images[:1],
    )


def _clip(value: str, limit: int) -> str:
    value = value.strip()
    return value[:limit]


def _pick(fields: dict[str, str], *names: str) -> str:
    lowered = {key.lower(): value for key, value in fields.items()}
    for name in names:
        found = lowered.get(name.lower(), "")
        if found:
            return found
    return ""


def _decode(data: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def _image_ext(data: bytes) -> str | None:
    if data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    return None


def _split_multipart(content_type: str, body: bytes) -> list[tuple[str, bytes]]:
    match = re.search(r"boundary=([^;]+)", content_type, flags=re.IGNORECASE)
    if not match:
        return []
    boundary = match.group(1).strip().strip('"').encode("utf-8", "replace")
    chunks = body.split(b"--" + boundary)
    parts: list[tuple[str, bytes]] = []
    for chunk in chunks[1:]:
        if chunk.startswith(b"--"):
            break
        if chunk.startswith(b"\r\n"):
            chunk = chunk[2:]
        elif chunk.startswith(b"\n"):
            chunk = chunk[1:]
        header_blob, sep, data = chunk.partition(b"\r\n\r\n")
        if not sep:
            header_blob, sep, data = chunk.partition(b"\n\n")
        if not sep:
            continue
        if data.endswith(b"\r\n"):
            data = data[:-2]
        elif data.endswith(b"\n"):
            data = data[:-1]
        parts.append((header_blob.decode("latin-1", "replace"), data))
    return parts


def _fields_from_text(text: str) -> dict[str, str]:
    stripped = text.strip()
    if not stripped:
        return {}
    head = stripped[:300].lower()
    if "<!doctype" in head or "<!entity" in head:
        return {}
    if stripped.startswith("<"):
        try:
            root = ET.fromstring(stripped)
        except ET.ParseError:
            return {}
        found: dict[str, str] = {}
        for element in root.iter():
            key = element.tag.split("}")[-1]
            value = (element.text or "").strip()
            if value and key not in found:
                found[key] = value
        return found
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return {}
        found = {}
        _walk_json(payload, found)
        return found
    return {}


def _walk_json(payload: object, found: dict[str, str]) -> None:
    if isinstance(payload, dict):
        nested: list[object] = []
        for key, value in payload.items():
            if isinstance(value, (dict, list)):
                nested.append(value)
            elif value is not None and key not in found:
                found[key] = str(value)
        for value in nested:
            _walk_json(value, found)
    elif isinstance(payload, list):
        for item in payload:
            _walk_json(item, found)
