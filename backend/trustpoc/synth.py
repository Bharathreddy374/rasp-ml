"""SYNTHETIC session generator for the ML shadow-mode demo.

Everything here is invented to exercise the ML pipeline end to end. The
distributions are plausible guesses, not measurements. Metrics from models
trained on this data say the pipeline works; they say nothing about real
accuracy. Real training data comes from the attack lab and verified-clean
traffic (design doc, Sections 6 and 10).
"""
import random

FAMILIES = ["hidden_root", "instrumentation", "emulator_virtual", "app_tamper_clone"]


def _probe(v, ms):
    return {"status": "ok", "v": v, "ms": round(ms, 3)}


def _err(ms):
    return {"status": "error", "err": "SecurityException", "ms": round(ms, 3)}


def genuine_base(r: random.Random) -> dict:
    dev = r.random() < 0.15
    acc = r.choices([[], ["com.lastpass.lpandroid/.Service"], ["a/.S", "b/.S"]], [0.8, 0.15, 0.05])[0]
    return {
        "root_su_paths": [], "root_su_which": False, "root_manager_packages": [],
        "root_magisk_mounts": False, "root_system_rw": False,
        "selinux_mode": "Enforcing" if r.random() > 0.002 else "Permissive",
        "props_test_keys": False, "emu_fingerprint": False, "emu_hardware": False, "emu_qemu_props": False,
        "sensor_count": r.randint(12, 45), "rt_tracer_pid": 0, "rt_debugger_connected": False,
        "rt_frida_maps": False, "rt_frida_threads": [], "rt_frida_port": False, "rt_xposed": False,
        "app_data_dir_ok": r.random() > 0.002, "ctx_developer_options": dev,
        "ctx_adb_enabled": dev and r.random() < 0.55, "ctx_accessibility_services": acc,
        "ctx_vpn": r.random() < 0.10,
    }


def to_payload(values: dict, r: random.Random, speed: float, errors: int = 0) -> dict:
    """speed scales probe timings (>1 = slower, e.g. hooked libc calls)."""
    probes = {}
    names = list(values)
    failing = set(r.sample(names, min(errors, len(names))))
    base = r.uniform(0.6, 1.6)  # device speed
    for k, v in values.items():
        ms = r.lognormvariate(-1.2, 0.5) * base * speed
        probes[k] = _err(ms) if k in failing else _probe(v, ms)
    return {"probes": probes}


def generate(n_genuine=6000, n_per_family=600, seed=7):
    """Returns (payloads, labels, variant). labels: dict family -> 0/1."""
    r = random.Random(seed)
    out = []

    for _ in range(n_genuine):
        v = genuine_base(r)
        errs = r.choices([0, 1, 2, 3], [0.85, 0.10, 0.03, 0.02])[0]
        out.append((to_payload(v, r, 1.0, errs), {f: 0 for f in FAMILIES}, "genuine"))

    for fam in FAMILIES:
        for i in range(n_per_family):
            hidden = i % 2 == 1
            v = genuine_base(r)
            speed, errs = 1.0, r.choices([0, 1], [0.85, 0.15])[0]
            labels = {f: 0 for f in FAMILIES}
            labels[fam] = 1
            if fam == "hidden_root":
                if not hidden:  # plain root: visible artefacts
                    v["root_manager_packages"] = ["com.topjohnwu.magisk"] if r.random() < 0.8 else []
                    v["root_magisk_mounts"] = r.random() < 0.7
                    v["root_su_paths"] = r.sample(["/system/bin/su", "/sbin/su", "/system/xbin/su"], r.randint(0, 2))
                else:  # DenyList / Shamiko: only side effects remain (assumed)
                    v["selinux_mode"] = "Permissive" if r.random() < 0.15 else "Enforcing"
                    v["root_magisk_mounts"] = r.random() < 0.2
                    speed = r.uniform(1.15, 1.7)
                    errs += r.choices([0, 1, 2, 3], [0.3, 0.3, 0.25, 0.15])[0]
                    v["ctx_developer_options"] = r.random() < 0.6
            elif fam == "instrumentation":
                if not hidden:
                    v["rt_frida_threads"] = r.sample(["gum-js-loop", "gmain", "gdbus", "pool-frida"], r.randint(1, 4))
                    v["rt_frida_maps"] = r.random() < 0.8
                    v["rt_frida_port"] = r.random() < 0.7
                    v["rt_xposed"] = r.random() < 0.15
                else:  # renamed Frida build: names gone, side effects remain (assumed)
                    v["rt_frida_threads"] = ["gmain"] if r.random() < 0.3 else []
                    speed = r.uniform(1.3, 2.2)
                    errs += r.choices([0, 1, 2], [0.4, 0.4, 0.2])[0]
                    v["rt_xposed"] = r.random() < 0.1
                if r.random() < 0.15:  # attack farms often combine with emulators
                    v.update({"emu_fingerprint": True, "emu_hardware": True, "sensor_count": r.randint(3, 10)})
                    labels["emulator_virtual"] = 1
            elif fam == "emulator_virtual":
                if not hidden:
                    v.update({"emu_fingerprint": r.random() < 0.9, "emu_hardware": r.random() < 0.9,
                              "emu_qemu_props": r.random() < 0.8, "props_test_keys": r.random() < 0.3})
                else:  # cloud phone / disguised emulator: identity spoofed, physics not (assumed)
                    v["emu_qemu_props"] = r.random() < 0.2
                    speed = r.uniform(0.5, 0.8)
                v["sensor_count"] = r.randint(2, 11)
                v["ctx_developer_options"] = r.random() < 0.9
                v["ctx_adb_enabled"] = v["ctx_developer_options"] and r.random() < 0.9
            elif fam == "app_tamper_clone":
                if not hidden:
                    v["app_data_dir_ok"] = False
                else:  # virtual space that fixes the path: weaker traces (assumed)
                    v["app_data_dir_ok"] = r.random() < 0.6
                    v["ctx_accessibility_services"] = ["io.va.exposed/.Host"] if r.random() < 0.5 else []
                    errs += r.choices([0, 1, 2], [0.5, 0.3, 0.2])[0]
            out.append((to_payload(v, r, speed, errs), labels, f"{fam}:{'hidden' if hidden else 'visible'}"))

    r.shuffle(out)
    return out
