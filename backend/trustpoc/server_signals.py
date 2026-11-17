"""Server-side catalogue signals (F286 - F350) computed from the request and history.

The phone never reports these. They come from what the server observes (client IP,
User-Agent, attestation chain) and from what it has seen before for the same install,
/24 network or attestation intermediate.

HistoryStore is in-process memory: it resets on restart and is not shared between
server instances. Production needs the same interface backed by Redis / Postgres.

Computed today (others need data this service does not have yet: GeoIP/ASN databases,
TLS fingerprints from the edge proxy, bank account IDs, payee data, an offline graph job):
  F299 user_agent_vs_build      F304 ip_changes_in_session   F305 request_timing_regularity
  F306 patch_level_regressed    F307 verified_boot_regressed F308 bootloader_state_changed
  F309 fingerprint_changed      F312 os_version_downgrade    F314 sdk_version_changed
  F315 app_version_regression   F329 time_since_install      F330 max_level_last_30d
  F331 level4plus_count_30d     F332 rule_hits_last_30d      F337 devices_per_attest_intermediate
  F339 devices_per_ip24
"""
import ipaddress
import re
import statistics
import threading
import time
from collections import OrderedDict, deque

DAY = 86400
SESSION_WINDOW = 30 * 60

# Regression signals that become Tier C reasons: values that should only move forward.
HISTORY_REASONS = {
    "F306": "HS_PATCH_REGRESSED",
    "F307": "HS_VERIFIED_BOOT_REGRESSED",
    "F308": "HS_BOOTLOADER_CHANGED",
    "F312": "HS_OS_DOWNGRADE",
    "F315": "HS_APP_VERSION_REGRESSED",
}

_UA = re.compile(r"Android ([\d.]+); (.+?) Build/")


def ip24(ip: str | None) -> str | None:
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        return None
    if addr.version == 4:
        return str(ipaddress.ip_network(f"{addr}/24", strict=False))
    return str(ipaddress.ip_network(f"{addr}/64", strict=False))


class HistoryStore:
    def __init__(self, max_installs: int = 50_000, max_keys: int = 50_000):
        self._lock = threading.Lock()
        self._installs: OrderedDict[str, dict] = OrderedDict()
        self._ip24: OrderedDict[str, dict[str, float]] = OrderedDict()
        self._intermediates: OrderedDict[str, dict[str, float]] = OrderedDict()
        self.max_installs, self.max_keys = max_installs, max_keys

    # ---- read: compute signals for the current request (before it is recorded) ----
    def compute(self, payload: dict, att, client_ip: str | None, user_agent: str | None,
                intermediate_serial: str | None, now: float | None = None) -> dict:
        now = now or time.time()
        install = str(payload.get("install_id", ""))[:64]
        dev = payload.get("device") or {}
        app = payload.get("app") or {}
        out: dict = {}

        m = _UA.search(user_agent or "")
        if m and dev:
            out["F299"] = (m.group(1) == str(dev.get("release", ""))
                           and m.group(2).strip() == str(dev.get("model", "")).strip())

        with self._lock:
            h = self._installs.get(install)
            net = ip24(client_ip)
            if net is not None:
                seen = {i for i, t in self._ip24.get(net, {}).items() if now - t < DAY}
                out["F339"] = len(seen | {install})
            if intermediate_serial:
                seen = {i for i, t in self._intermediates.get(intermediate_serial, {}).items() if now - t < DAY}
                out["F337"] = len(seen | {install})
            if h is None:
                out["F329"] = 0
                return out

            last = h["last"]
            out["F329"] = int(now - h["first_seen"])
            recent_ips = {e[1] for e in h["events"] if now - e[0] < SESSION_WINDOW and e[1]}
            out["F304"] = len(recent_ips | ({client_ip} if client_ip else set())) - 1 if recent_ips else 0
            times = [e[0] for e in h["events"]][-9:] + [now]
            gaps = [b - a for a, b in zip(times, times[1:])]
            if len(gaps) >= 5 and statistics.mean(gaps) > 0:
                out["F305"] = round(statistics.pstdev(gaps) / statistics.mean(gaps), 3)

            month = [e for e in h["events"] if now - e[0] < 30 * DAY]
            out["F330"] = max((e[2] for e in month), default=0)
            out["F331"] = sum(1 for e in month if e[2] >= 4)
            out["F332"] = sum(e[3] for e in month)

            patch, last_patch = dev.get("security_patch"), last.get("security_patch")
            if patch and last_patch:
                out["F306"] = str(patch) < str(last_patch)
            if dev.get("fingerprint") and last.get("fingerprint"):
                out["F309"] = dev["fingerprint"] != last["fingerprint"]
            sdk, last_sdk = dev.get("sdk_int"), last.get("sdk_int")
            if isinstance(sdk, int) and isinstance(last_sdk, int):
                out["F312"] = sdk < last_sdk
                out["F314"] = sdk != last_sdk
            vc, last_vc = app.get("version_code"), last.get("version_code")
            if isinstance(vc, int) and isinstance(last_vc, int):
                out["F315"] = vc < last_vc
            if att is not None and att.trustworthy:
                if last.get("device_locked") is not None and att.device_locked is not None:
                    out["F308"] = att.device_locked != last["device_locked"]
                if last.get("boot") == "Verified" and att.verified_boot_state not in (None, "Verified"):
                    out["F307"] = True
                elif last.get("boot") is not None and att.verified_boot_state is not None:
                    out["F307"] = False
        return out

    # ---- write: remember this request once it has been decided ----
    def record(self, payload: dict, att, client_ip: str | None, intermediate_serial: str | None,
               level: int, reason_count: int, now: float | None = None) -> None:
        now = now or time.time()
        install = str(payload.get("install_id", ""))[:64]
        if not install:
            return
        dev = payload.get("device") or {}
        app = payload.get("app") or {}
        with self._lock:
            h = self._installs.pop(install, None) or {
                "first_seen": now, "events": deque(maxlen=200), "last": {}}
            h["events"].append((now, client_ip, level, reason_count))
            last = h["last"]
            for k in ("security_patch", "fingerprint", "sdk_int"):
                if dev.get(k) is not None:
                    last[k] = dev[k]
            if app.get("version_code") is not None:
                last["version_code"] = app["version_code"]
            if att is not None and att.trustworthy:
                last["device_locked"] = att.device_locked
                last["boot"] = att.verified_boot_state
            self._installs[install] = h
            while len(self._installs) > self.max_installs:
                self._installs.popitem(last=False)

            net = ip24(client_ip)
            if net is not None:
                self._touch(self._ip24, net, install, now)
            if intermediate_serial:
                self._touch(self._intermediates, intermediate_serial, install, now)

    def _touch(self, table: OrderedDict, key: str, install: str, now: float) -> None:
        bucket = table.pop(key, None) or {}
        bucket[install] = now
        if len(bucket) > 5000:  # keep the newest entries only
            bucket = dict(sorted(bucket.items(), key=lambda kv: kv[1])[-5000:])
        table[key] = bucket
        while len(table) > self.max_keys:
            table.popitem(last=False)
