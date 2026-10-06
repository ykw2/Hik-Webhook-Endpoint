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


FACE_CODES = {75, 38, 76, 112, 113}
CARD_CODES = {1, 39, 16, 17}
FINGER_CODES = {2, 3, 18}
HEARTBEAT_MINOR = 77
LOCK_CODES = {21, 22}


def is_heartbeat(event_type: str) -> bool:
    return event_type.lower().replace("_", "") == "heartbeat"


def is_heartbeat_signal(event_type: str, raw_text: str) -> bool:
    fields = _access_fields(raw_text)
    if is_heartbeat(event_type) or is_heartbeat(_pick(fields, "eventType")):
        return True
    return _sub_code(fields) == HEARTBEAT_MINOR


def is_ignored_event(event_type: str, raw_text: str) -> bool:
    if is_heartbeat_signal(event_type, raw_text):
        return True
    return _sub_code(_access_fields(raw_text)) in LOCK_CODES


def heartbeat_device(raw_text: str, source_ip: str) -> dict[str, str] | None:
    fields = _access_fields(raw_text)
    mac = _normalize_mac(_pick(fields, "macAddress", "mac"))
    serial = _clip(_pick(fields, "shortSerialNumber", "serialNumber", "deviceID"), 80)
    ip = _clip(_pick(fields, "ipAddress", "ip", "deviceIP") or source_ip, 80)
    name = _clip(_pick(fields, "deviceName", "channelName", "device_name"), 80)
    if mac:
        key = "mac:" + mac
    elif serial:
        key = "sn:" + serial
    elif ip:
        key = "ip:" + ip
    else:
        return None
    return {"device_key": key, "name": name, "ip": ip, "mac": mac}


def _normalize_mac(value: str) -> str:
    raw = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(raw) != 12:
        return ""
    return ":".join(raw[index : index + 2] for index in range(0, 12, 2)).lower()


def door_info(raw_text: str) -> dict[str, str]:
    empty = {
        "open_method": "",
        "person_name": "",
        "employee_no": "",
        "door_no": "",
        "card_no": "",
        "device_name": "",
    }
    if not raw_text.strip():
        return empty
    fields = _access_fields(raw_text)
    if not _is_access(fields) or is_heartbeat(_pick(fields, "eventType")):
        return empty
    if _sub_code(fields) in {HEARTBEAT_MINOR, *LOCK_CODES}:
        return empty
    person = _clip(_pick(fields, "name", "personName", "employeeName"), 80)
    employee = _clip(_pick(fields, "employeeNoString", "employeeNo", "employeeNoStr"), 40)
    card = _clip(_pick(fields, "cardNo", "cardNumber"), 40)
    if not person and (employee or card):
        person = "未知人員"
    return {
        "open_method": _verification_label(fields),
        "person_name": person,
        "employee_no": employee,
        "door_no": _clip(_pick(fields, "doorNo", "devNo", "doorID", "doorId"), 20),
        "card_no": card,
        "device_name": _clip(_pick(fields, "deviceName", "device_name"), 80),
    }


def _is_access(fields: dict[str, str]) -> bool:
    event_type = _pick(fields, "eventType", "event_type").lower().replace("_", "")
    major = _pick(fields, "majorEventType", "major").strip().lower()
    return event_type == "accesscontrollerevent" or major in {"5", "0x5"}


def _sub_code(fields: dict[str, str]) -> int | None:
    raw = _pick(fields, "subEventType", "sub_event_type", "minor")
    if not raw:
        return None
    text = raw.strip().lower()
    try:
        if text.startswith("0x"):
            return int(text, 16)
        return int(float(text))
    except ValueError:
        return None


def _verification_label(fields: dict[str, str]) -> str:
    code = _sub_code(fields)
    if code in FACE_CODES:
        return "人臉辨識通行"
    if code in CARD_CODES:
        return "刷卡通行"
    if code in FINGER_CODES:
        return "指紋辨識通行"
    description = _pick(fields, "eventDescription", "label", "minorEventDesc").lower()
    if "face" in description or "人臉" in description or "人脸" in description:
        return "人臉辨識通行"
    if "card" in description or "刷卡" in description:
        return "刷卡通行"
    if "finger" in description or "指紋" in description or "指纹" in description:
        return "指紋辨識通行"
    shown = code if code is not None else "未知"
    return f"門禁驗證 (代碼:{shown})"


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
    face_image: tuple[str, bytes] | None = None
    if content_type.lower().startswith("multipart/"):
        for headers, data in _split_multipart(content_type, body):
            image = _image_ext(data)
            if image:
                item = (image, data)
                if _is_face_part(headers):
                    face_image = item
                elif not images:
                    images.append(item)
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

    preview = _fields_from_text(text)
    if not _pick(preview, "eventType", "event_type") and _sub_code(preview) is None:
        embedded = _best_event_json(text) or _best_event_json(_decode(body))
        if embedded:
            text = embedded
    if len(text) > RAW_LIMIT:
        text = text[:RAW_LIMIT] + "\n\n…（內容已截斷）"

    fields = _access_fields(text)
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
        images=[face_image] if face_image else images[:1],
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


def _is_face_part(headers: str) -> bool:
    text = headers.lower()
    return "face" in text or "human" in text or "人臉" in text


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


def _access_fields(raw_text: str) -> dict[str, str]:
    fields = _fields_from_text(raw_text)
    if _pick(fields, "eventType", "event_type") or _sub_code(fields) is not None:
        return fields
    blob = _best_event_json(raw_text)
    if not blob:
        return fields
    return _fields_from_text(blob) or fields


def _best_event_json(text: str) -> str:
    if not text or "{" not in text:
        return ""
    chosen = ""
    for chunk in _extract_json_objects(text):
        try:
            obj = json.loads(chunk)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        if "AccessControllerEvent" in obj or "eventType" in obj:
            return chunk
        if not chosen:
            chosen = chunk
    return chosen


def _extract_json_objects(text: str) -> list[str]:
    results: list[str] = []
    open_brackets = 0
    start = -1
    limit = min(len(text), 2_000_000)
    for index in range(limit):
        char = text[index]
        if char == "{":
            if open_brackets == 0:
                start = index
            open_brackets += 1
            if open_brackets > 80 or (start >= 0 and index - start > 400_000):
                open_brackets = 0
                start = -1
        elif char == "}" and open_brackets:
            open_brackets -= 1
            if open_brackets == 0 and start != -1:
                results.append(text[start : index + 1])
                start = -1
                if len(results) >= 20:
                    break
    return results


def _walk_json(payload: object, found: dict[str, str]) -> None:
    if isinstance(payload, dict):
        nested: list[object] = []
        for key, value in payload.items():
            if isinstance(value, (dict, list)):
                nested.append(value)
            elif value is not None and key not in found and str(value).strip():
                found[key] = str(value).strip()
        for value in nested:
            _walk_json(value, found)
    elif isinstance(payload, list):
        for item in payload:
            _walk_json(item, found)
