"""Request contract for POST /v1/collect: the `rasp_collect_v2` payload.

Validation is strict on shape and size and tolerant on content: a malformed request is
rejected with 422 and a precise message, while unknown signal IDs and unknown extra
fields are kept (signals) or ignored (top level) so a newer app does not break an older
server.

    {
      "schema": "rasp_collect_v2",
      "action": "transfer",
      "context_keys": {"install_id": "...", "session_id": "..."},
      "device": {"manufacturer", "model", "android_release", "sdk_int", "fingerprint",
                 "security_patch", "scan_timestamp"},
      "app": {"version_code"},
      "device_context": {"sim_country", "network_country", "timezone", "locale",       (optional)
                         "network_type", "boot_count", "uptime_ms", "android_id_hash"},
      "signals": {"F016": 0, "F018": ["release-keys", 0], ..., "battery_temp_c": 32.8},
      "unknown": ["F034", ...],
      "failed_groups": []
    }

A signal is either a bare value (bool / number / short text) or a pair [value, risk],
where risk is the probe's own verdict: 0 SAFE, 1 INFO, 2 SUSPICIOUS, 3 ALERT.
"""
import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_NAME = "rasp_collect_v2"
ACTIONS = ("login", "view_balance", "add_payee", "transfer", "high_value_transfer")

MAX_SIGNALS = 600
MAX_TEXT = 256
SIGNAL_ID = re.compile(r"^F\d{3}$")
EXTRA_SIGNAL_KEYS = {"battery_temp_c"}  # non-catalogue values the app also reports
ID_TEXT = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
PROBE_GROUPS = {
    "attestation", "device_static", "app_integrity", "runtime_hooking", "memory_procfs",
    "timing", "sensor_touch", "risky_context", "server_side", "probe_health",
}


def _clean(text: str) -> str:
    """Remove NUL characters. Android's /proc files end some strings with one (for example
    /proc/self/attr/current), and PostgreSQL cannot store NUL in text or JSONB."""
    return text.replace("\x00", "")


def _scalar(v: Any, where: str) -> Any:
    """Validate one signal value and return it cleaned."""
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        if isinstance(v, float) and (v != v or v in (float("inf"), float("-inf"))):
            raise ValueError(f"{where}: non-finite number")
        return v
    if isinstance(v, str):
        v = _clean(v)
        if len(v) > MAX_TEXT:
            raise ValueError(f"{where}: text longer than {MAX_TEXT} characters")
        return v
    raise ValueError(f"{where}: must be a boolean, number or text")


class ContextKeys(BaseModel):
    install_id: str
    session_id: str

    @field_validator("install_id", "session_id")
    @classmethod
    def _ids(cls, v: str) -> str:
        if not ID_TEXT.match(v):
            raise ValueError("must be 1-128 characters of letters, digits and _ . : -")
        return v


class Device(BaseModel):
    manufacturer: str = Field(max_length=64)
    model: str = Field(max_length=64)
    android_release: str = Field(max_length=32)
    sdk_int: int = Field(ge=1, le=100)
    fingerprint: str = Field(max_length=256)
    security_patch: str = Field(default="", max_length=32)
    scan_timestamp: str = Field(max_length=40)

    @field_validator("manufacturer", "model", "android_release", "fingerprint", "security_patch", mode="before")
    @classmethod
    def _no_nul(cls, v):
        return _clean(v) if isinstance(v, str) else v

    @field_validator("scan_timestamp")
    @classmethod
    def _iso(cls, v: str) -> str:
        parse_timestamp(v)
        return v


class App(BaseModel):
    version_code: int = Field(ge=0)


class DeviceContext(BaseModel):
    """Optional facts for server-side signals; every field may be missing."""
    model_config = ConfigDict(extra="ignore")

    sim_country: str | None = Field(default=None, pattern=r"^[a-z]{2}$")
    network_country: str | None = Field(default=None, pattern=r"^[a-z]{2}$")
    timezone: str | None = Field(default=None, max_length=64)
    locale: str | None = Field(default=None, max_length=35)
    network_type: str | None = Field(default=None, pattern=r"^(wifi|cellular|ethernet|vpn|other|none)$")
    boot_count: int | None = Field(default=None, ge=0)
    uptime_ms: int | None = Field(default=None, ge=0)
    android_id_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("sim_country", "network_country", mode="before")
    @classmethod
    def _empty_is_none(cls, v):
        return None if v in ("", None) else str(v).lower()

    @property
    def locale_country(self) -> str | None:
        """'en-IN' -> 'in'; None when the locale has no region."""
        if not self.locale:
            return None
        parts = self.locale.replace("_", "-").split("-")
        region = next((p for p in parts[1:] if len(p) == 2 and p.isalpha()), None)
        return region.lower() if region else None


class CollectPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    schema_name: str = Field(alias="schema")
    action: str
    context_keys: ContextKeys
    device: Device
    app: App
    device_context: DeviceContext | None = None
    signals: dict[str, Any]
    unknown: list[str] = Field(default_factory=list)
    failed_groups: list[str] = Field(default_factory=list)

    @field_validator("schema_name")
    @classmethod
    def _schema(cls, v: str) -> str:
        if v != SCHEMA_NAME:
            raise ValueError(f"must be '{SCHEMA_NAME}'")
        return v

    @field_validator("action")
    @classmethod
    def _action(cls, v: str) -> str:
        if v not in ACTIONS:
            raise ValueError(f"must be one of {', '.join(ACTIONS)}")
        return v

    @field_validator("signals")
    @classmethod
    def _signals(cls, signals: dict[str, Any]) -> dict[str, Any]:
        if len(signals) > MAX_SIGNALS:
            raise ValueError(f"at most {MAX_SIGNALS} signals")
        cleaned: dict[str, Any] = {}
        for key, entry in signals.items():
            if not (SIGNAL_ID.match(key) or key in EXTRA_SIGNAL_KEYS):
                raise ValueError(f"{key!r}: signal IDs look like F016")
            if isinstance(entry, list):
                if len(entry) != 2:
                    raise ValueError(f"{key}: a pair must be [value, risk]")
                risk = entry[1]
                if isinstance(risk, bool) or not isinstance(risk, int) or not 0 <= risk <= 3:
                    raise ValueError(f"{key}: risk must be an integer 0-3")
                cleaned[key] = [_scalar(entry[0], key), risk]
            else:
                cleaned[key] = _scalar(entry, key)
        return cleaned

    @field_validator("unknown")
    @classmethod
    def _unknown(cls, ids: list[str]) -> list[str]:
        if len(ids) > MAX_SIGNALS:
            raise ValueError(f"at most {MAX_SIGNALS} entries")
        bad = [i for i in ids if not (isinstance(i, str) and SIGNAL_ID.match(i))]
        if bad:
            raise ValueError(f"not signal IDs: {bad[:3]}")
        return ids

    @field_validator("failed_groups")
    @classmethod
    def _groups(cls, groups: list[str]) -> list[str]:
        bad = [g for g in groups if g not in PROBE_GROUPS]
        if bad:
            raise ValueError(f"unknown probe groups: {bad[:3]}")
        return groups

    @model_validator(mode="after")
    def _no_overlap(self) -> "CollectPayload":
        both = sorted(set(self.signals) & set(self.unknown))
        if both:
            raise ValueError(f"signals reported both measured and unknown: {both[:3]}")
        return self


def parse_timestamp(value: str) -> datetime:
    """ISO-8601 with a UTC offset, e.g. 2026-11-17T23:54:56+05:30. Returns an aware UTC datetime."""
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("must be ISO-8601, e.g. 2026-11-17T23:54:56+05:30") from exc
    if t.tzinfo is None:
        raise ValueError("must include a UTC offset, e.g. +05:30 or Z")
    return t.astimezone(timezone.utc)
