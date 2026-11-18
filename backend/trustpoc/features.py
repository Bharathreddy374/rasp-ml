"""Turn a device payload into a fixed numeric feature vector for the ML models.

Same names and order everywhere (training, scoring, dashboard). A probe that
errored or is missing becomes NaN, never 0: "unknown" is not "clean"
(design doc, Section 4).
"""
import math

FEATURES = [
    "root_su_paths_count", "root_su_which", "root_manager_count", "root_magisk_mounts",
    "root_system_rw", "selinux_not_enforcing", "props_test_keys",
    "emu_fingerprint", "emu_hardware", "emu_qemu_props", "sensor_count",
    "rt_tracer_nonzero", "rt_debugger", "rt_frida_maps", "rt_frida_threads_count",
    "rt_frida_port", "rt_xposed", "app_data_dir_bad",
    "ctx_developer_options", "ctx_adb_enabled", "ctx_accessibility_count", "ctx_vpn",
    "probe_error_count", "probe_total_ms", "libc_open_us",
]

NAN = float("nan")


def _get(probes: dict, name: str):
    p = probes.get(name)
    if not isinstance(p, dict) or p.get("status") != "ok":
        return None
    return p.get("v")


def _b(v) -> float:
    return NAN if v is None else float(bool(v))


def _n(v) -> float:
    return NAN if v is None else float(len(v) if isinstance(v, list) else v)


def extract(payload: dict) -> list[float]:
    p = payload.get("probes", {}) or {}
    selinux = _get(p, "selinux_mode")
    tracer = _get(p, "rt_tracer_pid")
    data_dir_ok = _get(p, "app_data_dir_ok")
    errors = sum(1 for x in p.values() if isinstance(x, dict) and x.get("status") == "error")
    row = {
        "root_su_paths_count": _n(_get(p, "root_su_paths")),
        "root_su_which": _b(_get(p, "root_su_which")),
        "root_manager_count": _n(_get(p, "root_manager_packages")),
        "root_magisk_mounts": _b(_get(p, "root_magisk_mounts")),
        "root_system_rw": _b(_get(p, "root_system_rw")),
        "selinux_not_enforcing": NAN if not isinstance(selinux, str) else float(selinux.lower() != "enforcing"),
        "props_test_keys": _b(_get(p, "props_test_keys")),
        "emu_fingerprint": _b(_get(p, "emu_fingerprint")),
        "emu_hardware": _b(_get(p, "emu_hardware")),
        "emu_qemu_props": _b(_get(p, "emu_qemu_props")),
        "sensor_count": _n(_get(p, "sensor_count")),
        "rt_tracer_nonzero": NAN if tracer is None else float(tracer != 0),
        "rt_debugger": _b(_get(p, "rt_debugger_connected")),
        "rt_frida_maps": _b(_get(p, "rt_frida_maps")),
        "rt_frida_threads_count": _n(_get(p, "rt_frida_threads")),
        "rt_frida_port": _b(_get(p, "rt_frida_port")),
        "rt_xposed": _b(_get(p, "rt_xposed")),
        "app_data_dir_bad": NAN if data_dir_ok is None else float(not data_dir_ok),
        "ctx_developer_options": _b(_get(p, "ctx_developer_options")),
        "ctx_adb_enabled": _b(_get(p, "ctx_adb_enabled")),
        "ctx_accessibility_count": _n(_get(p, "ctx_accessibility_services")),
        "ctx_vpn": _b(_get(p, "ctx_vpn")),
        "probe_error_count": float(errors),
        "probe_total_ms": _n(_get(p, "scan_total_ms")),     # F221: whole scan wall time (ms)
        "libc_open_us": _n(_get(p, "libc_open_us")),        # F211: libc open() latency (us)
    }
    return [row[f] for f in FEATURES]


def is_nan(x: float) -> bool:
    return isinstance(x, float) and math.isnan(x)
