import json
import os
from datetime import datetime
from typing import Any, Dict

import yaml

IOC_DOMAIN = "domain"
IOC_IP = "ip"
IOC_EMAIL = "email"
IOC_HASH = "hash"
IOC_UNKNOWN = "unknown"


def load_yaml(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


def save_json(data: Any, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def utc_now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def detect_ioc_type(value: str) -> str:
    value = value.strip()

    if "@" in value and "." in value.split("@")[-1]:
        return IOC_EMAIL

    parts = value.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return IOC_IP

    hex_chars = set("0123456789abcdefABCDEF")
    if len(value) in (32, 40, 64) and all(c in hex_chars for c in value):
        return IOC_HASH

    if "." in value:
        return IOC_DOMAIN

    return IOC_UNKNOWN
