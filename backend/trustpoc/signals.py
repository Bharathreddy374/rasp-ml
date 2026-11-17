"""Schema-2 device signals (feature catalogue IDs) -> the named probes the rules and ML use.

The app sends  "signals": {"F037": [value, risk], ...}  where risk is the probe's own
verdict: 0 SAFE, 1 INFO, 2 SUSPICIOUS, 3 ALERT. Values are typed (bool / number / short
text). Nothing here parses display text: detection comes from the probe's verdict, and
numbers come from typed values.

Signals listed in "unknown" are placeholder probes on the device. They, and any ID that
is simply missing, stay unknown: a probe that is absent becomes NaN for the ML and is
ignored by the rules, never treated as clean.
"""
from dataclasses import dataclass, field

SAFE, INFO, SUSPICIOUS, ALERT = 0, 1, 2, 3

# Probe groups that, when they fail on the device, are reported as errored probes.
GROUPS = ("attestation", "device_static", "app_integrity", "runtime_hooking", "memory_procfs",
          "timing", "sensor_touch", "risky_context", "probe_health")

# Root manager signal -> package name the rules know (rules.ROOT_MANAGER_PACKAGES).
ROOT_MANAGERS = {"F043": "com.topjohnwu.magisk", "F045": "me.weishu.kernelsu", "F046": "me.bmax.apatch"}

# probe name -> (signal IDs, minimum risk that counts as "detected")
ANY_FLAGGED = {
    "root_su_which": (("F041",), SUSPICIOUS),
    # F054: setuid binaries (stock Android has none since 4.3)
    "root_su_exec": (("F053", "F054"), ALERT),
    "root_magisk_mounts": (("F047", "F060"), SUSPICIOUS),
    "root_system_rw": (("F050", "F051"), SUSPICIOUS),
    # F026: android.os.Build fields disagree with the properties they come from (spoofing)
    "root_dangerous_props": (("F016", "F017", "F026"), ALERT),
    "props_test_keys": (("F018",), SUSPICIOUS),
    "rt_debugger_connected": (("F117", "F118", "F121"), SUSPICIOUS),
    # F115: native libraries mapped from writable / foreign paths; F137: injector traces
    # F132: frida-server files; F196: Frida / hook thread names in this process
    "rt_frida_maps": (("F124", "F125", "F133", "F115", "F137", "F132", "F196"), ALERT),
    # Emulator: sensor axes with exactly zero noise, or most samples identical (synthetic sensors)
    "emu_static_sensors": (("F231", "F232", "F233", "F240", "F241", "F242", "F243", "F247"), SUSPICIOUS),
    # F131: D-Bus AUTH answered like frida-server
    "rt_frida_port": (("F129", "F130", "F131"), ALERT),
    # F145: hook loader as native bridge; F166: hooked methods flagged native; F171: hook classes loadable
    "rt_xposed": (("F138", "F139", "F140", "F141", "F142", "F143", "F145", "F166", "F171"), ALERT),
    # F078: installed vs on-disk signing certificate differ; F083: APK Signing Block missing
    "app_cert_inconsistent": (("F078", "F083"), ALERT),
    # Native probes: libc entry points patched vs the file on disk (F146-F155), GOT redirected
    # (F156/F157), libc vs raw syscall disagreement (F159), JNI table outside libart (F163),
    # our own native code patched (F360) or loaded from elsewhere (F368).
    "rt_code_patched": (("F146", "F147", "F148", "F149", "F150", "F151", "F152", "F153", "F154", "F155",
                         "F156", "F157", "F159", "F163", "F360", "F368"), ALERT),
    # Context: INFO already means "on" for these settings (developer options reports INFO).
    "ctx_developer_options": (("F278",), INFO),
    "ctx_adb_enabled": (("F279", "F280"), INFO),
    "ctx_vpn": (("F282",), INFO),
}

# probe name -> signal IDs; value is the list of flagged IDs (rules treat non-empty as hit)
LIST_FLAGGED = {
    # F039: found by raw syscall; F040: libc and raw syscall disagree (a hook is hiding root files)
    "root_su_paths": ("F037", "F038", "F039", "F040"),
    "rt_frida_threads": ("F126", "F127", "F128"),
    "ctx_accessibility_services": ("F271", "F272"),
}

# Every signal consumed above; ALERTs outside this set are reported separately.
# Virtual-app / clone evidence: data dir shape, unusual dir, virtual-space markers, process name.
CLONE = ("F098", "F099", "F108", "F109")

MAPPED = ({i for ids, _ in ANY_FLAGGED.values() for i in ids}
          | {i for ids in LIST_FLAGGED.values() for i in ids}
          | set(ROOT_MANAGERS) | set(CLONE) | {"F031", "F116", "F255"})

# Signals that fingerprint the installed APK, compared with config "release_manifests".
APK_FIELDS = {"F084": "dex_digest", "F086": "so_digest", "F090": "arsc_crc",
              "F091": "manifest_crc", "F092": "assets_digest"}


def props_vs_attestation(payload: dict, att) -> bool | None:
    """F025: True when the device's reported patch level or Android version disagrees with the
    hardware-attested values (property spoofing, e.g. to pass Play Integrity). None if unknown."""
    if att is None or not att.trustworthy:
        return None
    dev = payload.get("device") or {}
    checks = []
    patch = str(dev.get("security_patch") or "")
    if att.os_patch_level and len(patch) >= 7 and patch[:4].isdigit() and patch[5:7].isdigit():
        checks.append(int(patch[:4] + patch[5:7]) != int(str(att.os_patch_level)[:6]))
    release = str(dev.get("release") or "").split(".")[0]
    if att.os_version and release.isdigit():
        checks.append(int(release) != att.os_version // 10000)
    return any(checks) if checks else None


def apk_matches_release(payload: dict, manifests: list) -> bool | None:
    """True if the installed APK matches a configured release, False if none, None if unknown."""
    if not manifests:
        return None
    signals = payload.get("signals") or {}
    reported = {field: e[0] for fid, field in APK_FIELDS.items() if (e := _entry(signals, fid)) is not None}
    if not reported:
        return None
    for m in manifests:
        if isinstance(m, dict) and all(m.get(f) == v for f, v in reported.items()):
            return True
    return False

EMU_FINGERPRINT = ("generic", "sdk_gphone", "emulator", "vbox86", "genymotion", "google_sdk")
EMU_HARDWARE = ("ranchu", "goldfish", "vbox86", "gce_x86", "cutf_cvm", "nox", "ttvm")
EMU_MODEL = ("sdk", "emulator", "android sdk built for")


@dataclass
class Converted:
    probes: dict
    device_signals: int = 0
    unknown: list[str] = field(default_factory=list)
    unmapped_alerts: list[str] = field(default_factory=list)


def _entry(signals: dict, fid: str):
    s = signals.get(fid)
    if isinstance(s, list) and len(s) == 2 and isinstance(s[1], int) and not isinstance(s[1], bool):
        return s[0], s[1]
    return None


def _ok(v) -> dict:
    return {"status": "ok", "v": v}


def to_probes(payload: dict) -> Converted:
    signals = payload.get("signals") or {}
    if not isinstance(signals, dict):
        signals = {}
    present = {fid: e for fid in signals if (e := _entry(signals, fid)) is not None}
    probes: dict = {}

    def flagged(fid: str, at: int):
        e = present.get(fid)
        return None if e is None else e[1] >= at

    for name, (ids, at) in ANY_FLAGGED.items():
        hits = [flagged(i, at) for i in ids]
        if any(h is not None for h in hits):
            probes[name] = _ok(any(bool(h) for h in hits))

    for name, ids in LIST_FLAGGED.items():
        hits = {i: flagged(i, SUSPICIOUS) for i in ids}
        if any(h is not None for h in hits.values()):
            probes[name] = _ok([i for i, h in hits.items() if h])

    managers = {fid: flagged(fid, SUSPICIOUS) for fid in ROOT_MANAGERS}
    if any(h is not None for h in managers.values()):
        probes["root_manager_packages"] = _ok([ROOT_MANAGERS[f] for f, h in managers.items() if h])

    if (e := present.get("F031")) is not None and isinstance(e[0], str):
        probes["selinux_mode"] = _ok(e[0])
    if (e := present.get("F116")) is not None:
        pid = e[0] if isinstance(e[0], int) and not isinstance(e[0], bool) else int(e[1] >= SUSPICIOUS)
        probes["rt_tracer_pid"] = _ok(pid)
    if (e := present.get("F255")) is not None and isinstance(e[0], (int, float)) and not isinstance(e[0], bool):
        probes["sensor_count"] = _ok(int(e[0]))
        probes["emu_low_sensors"] = _ok(e[0] < 5)

    data_dir = [flagged(i, SUSPICIOUS) for i in CLONE]
    if any(h is not None for h in data_dir):
        probes["app_data_dir_ok"] = _ok(not any(bool(h) for h in data_dir))

    # Emulator facts come from the signed device block, not from a catalogue signal.
    dev = payload.get("device") or {}
    if isinstance(dev, dict) and dev:
        fp = str(dev.get("fingerprint", "")).lower()
        hw = f'{dev.get("hardware", "")} {dev.get("board", "")}'.lower()
        model = f'{dev.get("model", "")} {dev.get("device", "")}'.lower()
        probes["emu_fingerprint"] = _ok(any(t in fp for t in EMU_FINGERPRINT))
        probes["emu_hardware"] = _ok(any(t in hw for t in EMU_HARDWARE))
        probes["emu_qemu_props"] = _ok(any(t in model for t in EMU_MODEL))

    for group in payload.get("failed_groups") or []:
        if group in GROUPS:
            probes[f"group_{group}"] = {"status": "error"}

    unknown = [u for u in (payload.get("unknown") or []) if isinstance(u, str)][:400]
    unmapped = sorted(fid for fid, e in present.items() if e[1] >= ALERT and fid not in MAPPED)
    return Converted(probes=probes, device_signals=len(present), unknown=unknown,
                     unmapped_alerts=unmapped)
