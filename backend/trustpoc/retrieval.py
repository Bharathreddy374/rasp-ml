"""Stage 4: backend data retrieval. Every catalogue signal the phone does not report.

The phone never sends F001-F015 (attestation), F286-F350 (network, history, graph) or
F025/F081/F088/F363-F365 (cross-checks). This stage computes each one it can, from:

  request   client IP, User-Agent, header order, proxy headers, the phone's clock
  context   the optional device_context block (SIM / network country, timezone, locale,
            network type, boot count, uptime, hashed Android ID)
  geo       trustpoc/geo.py: IP scope always; country / ASN / Tor when the data files exist
  database  ONE query (store.lookup): this install's history, counts per /24 network, ASN,
            sensor signature and Android ID, and the install's device-graph component
  config    release manifest and signing certificate (config.json)

Every signal it cannot compute is listed in `not_computed` with the reason, so a missing
value is never mistaken for a clean one. See BACKEND_SIGNALS for the full list.
"""
import hashlib
import ipaddress
import math
import re
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import normalize
from .geo import GeoIP
from .store import LookupQuery

CLOCK_SKEW_LIMIT_S = 30 * 60
SESSION_WINDOW_S = 30 * 60
UPTIME_DRIFT_LIMIT_S = 300
REINSTALL_LIMIT = 3
FARM_SCORE_LIMIT = 0.7
_UA = re.compile(r"Android ([\d.]+); (.+?) Build/")
PROXY_HEADERS = ("via", "forwarded", "x-forwarded-for", "x-real-ip", "x-proxy-id", "proxy-connection")

# Why a signal is not computed. The phrasing ends up in API responses and the database.
NO_ATTESTATION = "needs hardware key attestation, which the payload does not carry"
NO_PLAY_INTEGRITY = "needs Play Integrity (Google Cloud project), not integrated"
NO_GEO = "needs IP data files (run tools/update_geo.py)"
NO_PUBLIC_IP = "client IP is not public (private / loopback), so it has no country or ASN"
NO_CONTEXT = "needs the device_context block from the app"
NO_HISTORY = "needs an earlier session of this install"
NO_BANK = "needs account / payee / fraud-outcome data from the bank, which this service does not receive"
NO_EDGE = "needs TLS / TCP data from an edge proxy in front of this service"

BACKEND_SIGNALS = {
    # attestation
    **{f"F{n:03d}": NO_ATTESTATION for n in range(1, 11)},
    **{f"F{n:03d}": NO_PLAY_INTEGRITY for n in range(11, 16)},
    "F025": NO_ATTESTATION,
    # network
    "F286": NO_GEO, "F287": NO_GEO, "F288": NO_GEO, "F289": NO_GEO, "F290": "needs a country-to-timezone table",
    "F291": NO_GEO, "F292": "", "F293": NO_GEO, "F294": NO_GEO, "F295": "", "F296": NO_EDGE,
    "F297": NO_EDGE, "F298": "", "F299": "User-Agent is not the app's Android client",
    "F300": "needs an authoritative DNS probe", "F301": NO_CONTEXT, "F302": NO_EDGE, "F303": NO_CONTEXT,
    "F304": NO_HISTORY, "F305": "needs 6 or more sessions of this install",
    # history
    "F306": NO_HISTORY, "F307": NO_ATTESTATION, "F308": NO_ATTESTATION, "F309": NO_HISTORY,
    "F310": NO_CONTEXT, "F311": NO_CONTEXT, "F312": NO_HISTORY, "F313": NO_HISTORY, "F314": NO_HISTORY,
    "F315": NO_HISTORY, **{f"F{n}": NO_ATTESTATION for n in range(316, 322)}, "F322": NO_BANK,
    "F323": NO_BANK, "F324": NO_ATTESTATION, "F325": "", "F326": NO_CONTEXT, "F327": NO_BANK,
    "F328": NO_BANK, "F329": "", "F330": NO_HISTORY, "F331": NO_HISTORY, "F332": NO_HISTORY,
    "F333": NO_HISTORY, "F334": NO_BANK, "F335": NO_BANK,
    # graph
    "F336": NO_BANK, "F337": NO_ATTESTATION, "F338": "needs sensor signals F255 and F256",
    "F339": NO_PUBLIC_IP, "F340": NO_GEO, "F341": NO_BANK, "F342": NO_BANK, "F343": "", "F344": "",
    "F345": "", "F346": NO_BANK, "F347": "", "F348": "", "F349": "", "F350": "",
    # cross-checks
    "F081": "no expected_cert_sha256 in config.json", "F088": "no release_manifests in config.json",
    "F363": NO_HISTORY, "F364": "the payload is not signed", "F365": "",
}


@dataclass
class Request:
    """What the HTTP layer knows about the call, independent of the payload."""
    client_ip: str | None
    user_agent: str | None
    payload_bytes: int
    header_names: list[str] = field(default_factory=list)  # in the order the client sent them
    proxy_headers: list[str] = field(default_factory=list)  # proxy headers present (when no proxy is trusted)
    ja3: str | None = None                                   # from a trusted edge proxy only


@dataclass
class Retrieved:
    server_signals: dict
    not_computed: dict
    history: dict
    checks: dict
    keys: dict                    # derived per-request keys stored with the session (asn, sensor_sig, ...)
    evidence: list[tuple[str, str]] = field(default_factory=list)
    anomaly_history: list[float] = field(default_factory=list)  # for F333, filled in after the model runs
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


def _value(entry):
    return None if entry is None else normalize.sig(entry).value


def sensor_signature(signals: dict) -> str | None:
    """Hash of the sensor hardware description: count, accelerometer vendor, quantisation step and
    power. Identical on phones of one model; on emulator farms identical across many installs."""
    if "F255" not in signals or "F256" not in signals:
        return None
    parts = [str(_value(signals.get(k))) for k in ("F255", "F256", "F254", "F258")]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def header_hash(names: list[str]) -> str | None:
    if not names:
        return None
    return hashlib.sha256(",".join(n.lower() for n in names).encode()).hexdigest()[:16]


def retrieve(store, geo: GeoIP | None, payload, req: Request, scan_time: datetime, config: dict,
             now: datetime | None = None) -> Retrieved:
    started = time.perf_counter()
    now = now or datetime.now(timezone.utc)
    install = payload.context_keys.install_id
    dev, app, ctx = payload.device, payload.app, payload.device_context
    sig: dict = {}
    evidence: list[tuple[str, str]] = []

    # ---- request and geo ----
    ip = geo.lookup(req.client_ip) if geo else None
    net = net24(req.client_ip)
    sensor_sig = sensor_signature(payload.signals)
    keys = {"asn": ip.asn if ip else None, "sensor_sig": sensor_sig,
            "android_id_hash": ctx.android_id_hash if ctx else None,
            "header_hash": header_hash(req.header_names), "ja3": req.ja3, "device_context": ctx.model_dump() if ctx else None}

    if ip:
        if ip.asn_type:
            sig["F287"] = ip.asn_type  # hosting | mobile | isp for public IPs; private / loopback / ... otherwise
        if ip.scope == "public":
            if ip.asn is not None:
                sig["F286"] = ip.asn
                sig["F294"] = ip.asn_type == "hosting"
                if sig["F294"]:
                    evidence.append(("C", "CX_HOSTING_IP"))
            if ip.country:
                sig["F288"] = ip.country
                if ctx and ctx.sim_country:
                    sig["F289"] = ip.country.lower() != ctx.sim_country
                    if sig["F289"]:
                        evidence.append(("C", "CX_COUNTRY_MISMATCH"))
                if ctx and ctx.locale_country:
                    sig["F291"] = ip.country.lower() != ctx.locale_country
            if ip.tor_exit is not None:
                sig["F293"] = ip.tor_exit
                if ip.tor_exit:
                    evidence.append(("C", "CX_TOR_EXIT"))

    device_vpn = normalize.sig(payload.signals["F282"]).risk if "F282" in payload.signals else None
    sig["F292"] = bool(req.proxy_headers) or bool(ip and ip.asn_type == "hosting") or bool(device_vpn and device_vpn >= 1) \
        or bool(ctx and ctx.network_type == "vpn")
    if req.proxy_headers:
        evidence.append(("C", "CX_PROXY_HEADERS"))
    if req.ja3:
        sig["F296"] = req.ja3
    if keys["header_hash"]:
        sig["F298"] = keys["header_hash"]
    m = _UA.search(req.user_agent or "")
    if m:
        sig["F299"] = m.group(1).split(".")[0] == dev.android_release.split(".")[0] and m.group(2).strip() == dev.model.strip()
    if ctx and ctx.network_type:
        sig["F301"] = ctx.network_type

    skew = (now - scan_time).total_seconds()
    sig["F365"] = int(skew * 1000)
    if abs(skew) > CLOCK_SKEW_LIMIT_S:
        evidence.append(("C", "CX_CLOCK_SKEW"))

    # ---- database: one round trip ----
    look = store.lookup(LookupQuery(install_id=install, now=now, net24=net, asn=keys["asn"],
                                    sensor_sig=sensor_sig, android_id_hash=keys["android_id_hash"]))
    prior = look.history
    times = [_t(r["received_at"]) for r in prior]  # newest first
    summary = {"sessions_seen": len(prior), "first_seen": None, "last_seen": None,
               "last_level": None, "max_level_30d": None, "clock_skew_s": round(skew, 1)}

    sig["F329"] = int((now - times[-1]).total_seconds()) if prior else 0
    sig["F348"] = round(sig["F329"] / 86400, 2)
    if prior:
        last = prior[0]
        ldev, lctx = last.get("device") or {}, last.get("context") or {}
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
        kernel_now, kernel_last = _value(payload.signals.get("F067")), _value(last.get("kernel"))
        if kernel_now is not None and kernel_last is not None:
            sig["F313"] = kernel_now != kernel_last
        if last.get("scan_time"):
            sig["F363"] = scan_time > _t(last["scan_time"])   # the phone's clock must move forward between sessions

        # boot count and uptime: a reset, or an uptime that does not fit the time that passed
        if ctx and ctx.boot_count is not None and isinstance(lctx.get("boot_count"), int):
            sig["F310"] = ctx.boot_count < lctx["boot_count"]
            if sig["F310"]:
                evidence.append(("C", "HS_BOOT_COUNT_RESET"))
            if ctx.boot_count == lctx["boot_count"] and ctx.uptime_ms is not None and isinstance(lctx.get("uptime_ms"), int):
                expected = lctx["uptime_ms"] + (scan_time - _t(last["scan_time"])).total_seconds() * 1000
                sig["F311"] = round(abs(ctx.uptime_ms - expected) / 1000, 1)   # seconds of drift
                if sig["F311"] > UPTIME_DRIFT_LIMIT_S:
                    evidence.append(("C", "HS_UPTIME_INCONSISTENT"))

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

        if ctx and ctx.network_type:
            day = [(r.get("context") or {}).get("network_type") for r, t in zip(prior, times) if now - t < timedelta(days=1)]
            seq = [n for n in reversed(day) if n] + [ctx.network_type]
            sig["F303"] = sum(1 for a, b in zip(seq, seq[1:]) if a != b)

    # network and device counts from the database
    if net:
        same_net_before = any(net24(r.get("client_ip")) == net and now - _t(r["received_at"]) < timedelta(days=1) for r in prior)
        sig["F339"] = look.net_installs_24h + (0 if same_net_before else 1)   # + this install if not counted yet
        is_new = not prior or now - times[-1] < timedelta(days=1)
        sig["F325"] = look.net_new_installs_24h + (1 if is_new and not same_net_before else 0)
        share = look.net_risky_sessions_30d / look.net_sessions_30d if look.net_sessions_30d else 0.0
        if ip and ip.tor_exit:
            share = max(share, 0.9)
        if ip and ip.asn_type == "hosting":
            share = max(share, 0.5)
        sig["F295"] = round(share, 3)   # 0 = nothing bad seen from this /24 in 30 days, 1 = all sessions risky
    if keys["asn"] is not None:
        sig["F340"] = look.asn_installs_24h + 1        # installs on this ASN in 24 h, this one included
    if sensor_sig:
        sig["F338"] = look.sensor_installs_24h + 1     # installs with identical sensor hardware in 24 h
    if keys["android_id_hash"]:
        sig["F326"] = look.aid_other_installs_30d   # other installs on this same phone in 30 days
        if sig["F326"] >= REINSTALL_LIMIT:
            evidence.append(("C", "HS_REINSTALLS"))

    # device graph: this install's connected component (shared /24 or shared Android ID, 7 days)
    g = look.graph
    size = g.members + 1
    sig["F343"] = sig["F349"] = size
    if g.members:
        sig["F344"] = round(g.emulator / g.members, 3)
        sig["F345"] = round(g.new / g.members, 3)
        sig["F347"] = round((g.level_sum / g.members - 1) / 4, 3)   # 0 = all level 1 ... 1 = all level 5
        worst = max(sig["F344"], sig["F345"], g.risky / g.members)
        sig["F350"] = round(min(1.0, math.log2(size) / 5) * worst, 3) if size >= 3 else 0.0
        if sig["F350"] >= FARM_SCORE_LIMIT:
            evidence.append(("C", "GR_FARM_CLUSTER"))
    else:
        sig["F344"] = sig["F345"] = sig["F347"] = sig["F350"] = 0.0

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

    # ---- what could not be computed, and why ----
    not_computed = {}
    for fid, reason in BACKEND_SIGNALS.items():
        if fid in sig or fid == "F333":   # F333 is filled in after the model runs
            continue
        if fid in ("F286", "F288", "F289", "F291", "F293", "F294", "F340") and ip and ip.scope != "public":
            reason = NO_PUBLIC_IP
        elif fid in ("F289", "F291") and ip and ip.scope == "public" and geo and geo.countries is not None:
            reason = NO_CONTEXT
        elif fid in ("F310", "F311", "F303") and ctx and prior:
            reason = "the previous session of this install has no device_context to compare with"
        not_computed[fid] = reason or "not enough data for this request"

    return Retrieved(server_signals=dict(sorted(sig.items())), not_computed=dict(sorted(not_computed.items())),
                     history=summary, checks=checks, keys=keys, evidence=evidence,
                     anomaly_history=[float(r["anomaly_pct"]) for r in prior[:5] if r.get("anomaly_pct") is not None],
                     retrieval_ms=round((time.perf_counter() - started) * 1000, 2))


def anomaly_trend(retrieved: Retrieved, current_pct: float | None) -> None:
    """F333: this session's anomaly percentile minus the mean of the install's last 5 sessions."""
    if current_pct is None or not retrieved.anomaly_history:
        retrieved.not_computed["F333"] = NO_HISTORY if not retrieved.anomaly_history else "the model did not score this session"
        return
    retrieved.server_signals["F333"] = round(current_pct - statistics.mean(retrieved.anomaly_history), 1)
    retrieved.server_signals = dict(sorted(retrieved.server_signals.items()))
