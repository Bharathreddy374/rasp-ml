"""Stage 3: backend data retrieval. Facts about this session that the phone cannot supply.

Three sources, each producing catalogue signals (the F-numbers match docs/FEATURES.md):

  request   what this HTTP request itself shows: client IP, User-Agent, the phone's clock
              F299 user_agent_vs_build   F339 devices_per_ip24 (24 h)   clock skew
  history   this install's earlier sessions, read from the database
              F304 ip_changes_in_session  F305 request_timing_regularity  F306 patch_level_regressed
              F309 fingerprint_changed    F312 os_version_downgrade       F314 sdk_version_changed
              F315 app_version_regression F329 time_since_install
              F330 max_level_last_30d     F331 level4plus_count_30d       F332 rule_hits_last_30d
  checks    comparisons against configuration (config.json)
              release manifest (F084-F092)   signing certificate (F076)

Anything that needs data this service does not have (GeoIP / ASN, TLS fingerprints, bank
accounts, a device graph) is not computed, and is not invented.

The result also lists `evidence`: (tier, reason code) pairs that feed the rules.
"""
import ipaddress
import re
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import normalize

CLOCK_SKEW_LIMIT_S = 30 * 60
SESSION_WINDOW_S = 30 * 60
_UA = re.compile(r"Android ([\d.]+); (.+?) Build/")


@dataclass
class Request:
    """What the HTTP layer knows about the call, independent of the payload."""
    client_ip: str | None
    user_agent: str | None
    payload_bytes: int


@dataclass
class Retrieved:
    server_signals: dict
    history: dict
    checks: dict
    evidence: list[tuple[str, str]] = field(default_factory=list)
    retrieval_ms: float = 0.0


def net24(ip: str | None) -> str | None:
    """The /24 (IPv4) or /64 (IPv6) network of an address, as text."""
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        return None
    return str(ipaddress.ip_network(f"{addr}/{24 if addr.version == 4 else 64}", strict=False))


def _t(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def retrieve(store, payload, req: Request, scan_time: datetime, config: dict,
             now: datetime | None = None) -> Retrieved:
    started = time.perf_counter()
    now = now or datetime.now(timezone.utc)
    install = payload.context_keys.install_id
    dev, app = payload.device, payload.app
    sig: dict = {}
    evidence: list[tuple[str, str]] = []

    # ---- request ----
    m = _UA.search(req.user_agent or "")
    if m:
        sig["F299"] = m.group(1).split(".")[0] == dev.android_release.split(".")[0] and m.group(2).strip() == dev.model.strip()
    skew = (now - scan_time).total_seconds()
    if abs(skew) > CLOCK_SKEW_LIMIT_S:
        evidence.append(("C", "CX_CLOCK_SKEW"))

    # ---- history ----
    net = net24(req.client_ip)
    prior, installs_on_net = store.lookup(install, net, now - timedelta(days=1), 200)  # one DB round trip
    summary = {"sessions_seen": len(prior), "first_seen": None, "last_seen": None,
               "last_level": None, "max_level_30d": None, "clock_skew_s": round(skew, 1)}
    if prior:
        times = [_t(r["received_at"]) for r in prior]  # newest first
        last = prior[0]
        ldev = last.get("device") or {}
        sig["F329"] = int((now - times[-1]).total_seconds())
        summary.update(first_seen=times[-1].isoformat(), last_seen=times[0].isoformat(), last_level=last.get("final_level"))

        if dev.security_patch and ldev.get("security_patch"):
            sig["F306"] = dev.security_patch < ldev["security_patch"]
            if sig["F306"]:
                evidence.append(("C", "HS_PATCH_REGRESSED"))
        if ldev.get("fingerprint"):
            sig["F309"] = dev.fingerprint != ldev["fingerprint"]
        if isinstance(ldev.get("sdk_int"), int):
            sig["F312"] = dev.sdk_int < ldev["sdk_int"]
            sig["F314"] = dev.sdk_int != ldev["sdk_int"]
            if sig["F312"]:
                evidence.append(("C", "HS_OS_DOWNGRADE"))
        if isinstance(last.get("app_version"), int):
            sig["F315"] = app.version_code < last["app_version"]
            if sig["F315"]:
                evidence.append(("C", "HS_APP_VERSION_REGRESSED"))

        month = [r for r, t in zip(prior, times) if now - t < timedelta(days=30)]
        levels = [r["final_level"] for r in month if r.get("final_level")]
        sig["F330"] = max(levels, default=0)
        sig["F331"] = sum(1 for lv in levels if lv >= 4)
        sig["F332"] = sum(int(r.get("reason_count") or 0) for r in month)
        summary["max_level_30d"] = sig["F330"]

        recent_ips = {r["client_ip"] for r, t in zip(prior, times)
                      if r.get("client_ip") and (now - t).total_seconds() < SESSION_WINDOW_S}
        sig["F304"] = max(len(recent_ips | ({req.client_ip} if req.client_ip else set())) - 1, 0) if recent_ips else 0
        gaps = [(a - b).total_seconds() for a, b in zip([now] + times[:9], times[:10])]
        if len(gaps) >= 5 and statistics.mean(gaps) > 0:
            sig["F305"] = round(statistics.pstdev(gaps) / statistics.mean(gaps), 3)
    else:
        sig["F329"] = 0

    if net:
        same_net_before = any(net24(r.get("client_ip")) == net and now - _t(r["received_at"]) < timedelta(days=1) for r in prior)
        sig["F339"] = installs_on_net + (0 if same_net_before else 1)  # + this install if it is not counted yet

    # ---- checks against configuration ----
    checks = {"release_manifest": None, "signing_cert": None}
    apk = normalize.apk_matches_release(payload.signals, config.get("release_manifests") or [])
    if apk is not None:
        checks["release_manifest"] = apk
        sig["F088"] = not apk
        if not apk:
            evidence.append(("B", "AP_CODE_MISMATCH"))
    cert = normalize.cert_matches(payload.signals, config.get("expected_cert_sha256") or [])
    if cert is not None:
        checks["signing_cert"] = cert
        sig["F081"] = cert
        if not cert:
            evidence.append(("B", "AP_CERT_MISMATCH"))

    return Retrieved(server_signals=dict(sorted(sig.items())), history=summary, checks=checks,
                     evidence=evidence, retrieval_ms=round((time.perf_counter() - started) * 1000, 2))
