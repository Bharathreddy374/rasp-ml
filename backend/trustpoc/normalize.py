"""Stage 2: turn the signals of a rasp_collect_v2 payload into the named probes that the
rules and the ML model consume.

The app sends two shapes of signal, and this module is the only place that interprets them:

    "F124": ["Clean", 0]   pair: [display value, risk]. The device's own verdict is the
                           risk (0 SAFE, 1 INFO, 2 SUSPICIOUS, 3 ALERT). Text is never parsed.
    "F146": 0              bare typed value. Meaning is fixed per signal ID below
                           (a count > 0, a flag, a "0"/"1" property, ...).

Principles
  * A signal whose meaning cannot be decided (a bare text where a number was expected, for
    example) is reported as `undecidable` and treated as MISSING, never as clean.
  * Missing, unknown and undecidable signals do not become probes. The ML feature builder turns
    an absent probe into NaN ("unknown is not clean").
  * Signals no rule uses are still stored. An ALERT outside the table below is reported in
    `unmapped_alerts` and counts as context (Tier C), not as proof.
"""
import re
from dataclasses import dataclass, field

SAFE, INFO, SUSPICIOUS, ALERT = 0, 1, 2, 3
_NUMBER = re.compile(r"^\s*(-?\d+(?:\.\d+)?)")


@dataclass(frozen=True)
class Sig:
    value: object
    risk: int | None  # None for a bare value


def sig(entry) -> Sig:
    if isinstance(entry, list):
        return Sig(entry[0], entry[1])
    return Sig(entry, None)


def number(value) -> float | None:
    """A bool, a number, or the leading number of a text such as '75 deleted mappings'."""
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        m = _NUMBER.match(value)
        return float(m.group(1)) if m else None
    return None


@dataclass(frozen=True)
class D:
    """How one signal counts as evidence.
    at:   a pair counts when its risk >= at
    bare: how to read a bare value (None = a bare value is undecidable for this signal)
          gt0 | gtN:<n> | zero | true | false | eq1 | eq0 | nonclean | has:<text>
    """
    at: int
    bare: str | None = None


# Texts that mean "nothing found" for signals that report names when something is found.
CLEAN_TEXT = {"", "0", "none", "clean", "not set", "not found", "false", "no",
              "libhoudini.so", "libndk_translation.so", "libnb.so"}


def evaluate(s: Sig, d: D) -> bool | None:
    """True = evidence present, False = checked and clean, None = cannot be decided."""
    if s.risk is not None:
        return s.risk >= d.at
    if d.bare is None:
        return None
    n = number(s.value)
    kind, _, arg = d.bare.partition(":")
    if kind == "gt0":
        return None if n is None else n > 0
    if kind == "gtN":
        return None if n is None else n > float(arg)
    if kind == "zero":
        return None if n is None or isinstance(s.value, str) else n == 0
    if kind == "true":
        return bool(s.value) if isinstance(s.value, bool) else (None if n is None else n > 0)
    if kind == "false":
        return (not s.value) if isinstance(s.value, bool) else None
    if kind == "eq1":
        return None if n is None else n == 1
    if kind == "eq0":
        return None if n is None else n == 0
    if kind == "nonclean":
        return str(s.value).strip().lower() not in CLEAN_TEXT
    if kind == "has":
        return arg in str(s.value).lower()
    return None


# ---------------------------------------------------------------------------------------
# What each probe is made of. A probe is "detected" when any of its signals is evidence.
# ---------------------------------------------------------------------------------------
FLAGS: dict[str, dict[str, D]] = {
    # root
    "root_su_which": {"F041": D(2)},
    "root_su_exec": {"F053": D(3), "F054": D(3, "gt0")},
    "root_magisk_mounts": {"F047": D(2), "F060": D(2)},
    "root_system_rw": {"F050": D(2), "F051": D(2)},
    "root_dangerous_props": {"F016": D(3, "eq1"), "F017": D(3, "eq0"), "F026": D(3, "gt0")},
    "props_test_keys": {"F018": D(2, "has:test-keys")},
    # debugger / instrumentation
    "rt_debugger_connected": {"F117": D(2), "F118": D(2), "F121": D(2)},
    "rt_frida_maps": {"F124": D(3), "F125": D(3), "F115": D(3, "gt0"), "F137": D(3, "gt0"),
                      "F132": D(3), "F196": D(3, "nonclean")},
    "rt_frida_port": {"F129": D(3), "F130": D(3), "F131": D(3, "true")},
    "rt_xposed": {**{f"F{n}": D(3) for n in range(138, 144)}, "F145": D(3, "nonclean"),
                  "F166": D(3, "gt0"), "F171": D(3, "gt0")},
    # native integrity: code patched in memory, GOT redirected, libc vs raw syscall disagree
    "rt_code_patched": {**{f"F{n}": D(3, "gt0") for n in range(146, 158)}, "F159": D(3, "gt0"),
                        "F163": D(3, "gt0"), "F360": D(3, "gt0"), "F368": D(3, "false")},
    # emulator: synthetic sensors (zero noise, replayed samples)
    "emu_static_sensors": {"F231": D(2, "zero"), "F232": D(2, "zero"), "F233": D(2, "zero"),
                           "F241": D(2, "zero"), "F242": D(2, "zero"), "F243": D(2, "zero"),
                           "F240": D(2, "gtN:30"), "F247": D(2, "gtN:30")},
    # app integrity
    "app_cert_inconsistent": {"F078": D(3, "true"), "F083": D(3, "false")},
    # context
    "ctx_developer_options": {"F278": D(1)},
    "ctx_adb_enabled": {"F279": D(1), "F280": D(1)},
    "ctx_vpn": {"F282": D(1)},
}

# Probes whose value is the list of the signals that fired (rules use "non-empty").
LISTS: dict[str, dict[str, D]] = {
    "root_su_paths": {"F037": D(2), "F038": D(2), "F039": D(2, "gt0"), "F040": D(2, "gt0")},
    "rt_frida_threads": {"F126": D(2), "F127": D(2), "F128": D(2)},
}
ROOT_MANAGERS = {"F043": "com.topjohnwu.magisk", "F045": "me.weishu.kernelsu", "F046": "me.bmax.apatch"}
DATA_DIR = {"F098": D(2), "F099": D(2), "F108": D(2), "F109": D(2, "true")}

MAPPED = (
    {i for ids in FLAGS.values() for i in ids} | {i for ids in LISTS.values() for i in ids}
    | set(ROOT_MANAGERS) | set(DATA_DIR) | {"F031", "F116", "F255", "F273", "F021"}
)

EMU_FINGERPRINT = ("generic", "sdk_gphone", "emulator", "vbox86", "genymotion", "google_sdk")
EMU_HARDWARE = ("ranchu", "goldfish", "vbox86", "gce_x86", "cutf_cvm", "nox", "ttvm")
EMU_MODEL = ("sdk", "emulator", "android sdk built for", "generic")


@dataclass
class Normalized:
    probes: dict                                    # name -> {"status": "ok", "v": ...}
    signals_received: int = 0
    unknown_reported: int = 0
    undecidable: list[str] = field(default_factory=list)
    unmapped_alerts: list[str] = field(default_factory=list)
    used: list[str] = field(default_factory=list)   # signal IDs that fed a probe


def _ok(v) -> dict:
    return {"status": "ok", "v": v}


def normalize(payload) -> Normalized:
    """`payload` is a validated schema.CollectPayload."""
    present = {k: sig(v) for k, v in payload.signals.items() if re.match(r"^F\d{3}$", k)}
    unknown = set(payload.unknown)
    out = Normalized(probes={}, signals_received=len(present), unknown_reported=len(unknown))
    used: set[str] = set()

    def decide(group: dict[str, D]):
        """-> (hits, decided) for the signals of one probe."""
        hits, decided = [], 0
        for fid, d in group.items():
            if fid not in present or fid in unknown:
                continue
            r = evaluate(present[fid], d)
            if r is None:
                out.undecidable.append(fid)
                continue
            decided += 1
            used.add(fid)
            if r:
                hits.append(fid)
        return hits, decided

    for name, group in FLAGS.items():
        hits, decided = decide(group)
        if decided:
            out.probes[name] = _ok(bool(hits))
    for name, group in LISTS.items():
        hits, decided = decide(group)
        if decided:
            out.probes[name] = _ok(hits)
    hits, decided = decide({fid: D(2, "gt0") for fid in ROOT_MANAGERS})
    if decided:
        out.probes["root_manager_packages"] = _ok([ROOT_MANAGERS[f] for f in hits])
    hits, decided = decide(DATA_DIR)
    if decided:
        out.probes["app_data_dir_ok"] = _ok(not hits)

    # typed values
    if "F031" in present and "F031" not in unknown and isinstance(present["F031"].value, str):
        out.probes["selinux_mode"] = _ok(present["F031"].value)
        used.add("F031")
    if "F116" in present and "F116" not in unknown and number(present["F116"].value) is not None:
        out.probes["rt_tracer_pid"] = _ok(int(number(present["F116"].value)))
        used.add("F116")
    if "F255" in present and "F255" not in unknown and number(present["F255"].value) is not None:
        count = int(number(present["F255"].value))
        out.probes["sensor_count"] = _ok(count)
        out.probes["emu_low_sensors"] = _ok(count < 5)
        used.add("F255")
    if "F273" in present and "F273" not in unknown and number(present["F273"].value) is not None:
        out.probes["ctx_accessibility_services"] = _ok(int(number(present["F273"].value)))
        used.add("F273")

    # emulator identity: from the device block and the SoC string (F021 "hardware / board")
    dev = payload.device
    fp, model = dev.fingerprint.lower(), f"{dev.manufacturer} {dev.model}".lower()
    out.probes["emu_fingerprint"] = _ok(any(t in fp for t in EMU_FINGERPRINT))
    out.probes["emu_qemu_props"] = _ok(any(t in model for t in EMU_MODEL))
    if "F021" in present and "F021" not in unknown:
        soc = str(present["F021"].value).lower()
        out.probes["emu_hardware"] = _ok(any(t in soc for t in EMU_HARDWARE))
        used.add("F021")

    for group in payload.failed_groups:
        out.probes[f"group_{group}"] = {"status": "error"}

    out.unmapped_alerts = sorted(
        fid for fid, s in present.items()
        if s.risk == ALERT and fid not in MAPPED and fid not in unknown)
    out.used = sorted(used)
    out.undecidable = sorted(set(out.undecidable))
    return out


# ---------------------------------------------------------------------------------------
# App identity checks that need configuration (config.json)
# ---------------------------------------------------------------------------------------
APK_FIELDS = {"F084": "dex_digest", "F086": "so_digest", "F090": "arsc_crc",
              "F091": "manifest_crc", "F092": "assets_digest"}


def apk_matches_release(signals: dict, manifests: list) -> bool | None:
    """True if the reported APK digests equal one configured release, False if none, None if
    nothing is configured or reported. See tools/apk_manifest.py."""
    if not manifests:
        return None
    reported = {field: sig(signals[fid]).value for fid, field in APK_FIELDS.items() if fid in signals}
    if not reported:
        return None
    return any(isinstance(m, dict) and all(m.get(f) == v for f, v in reported.items()) for m in manifests)


def cert_matches(signals: dict, expected: list) -> bool | None:
    """F076 is the SHA-256 of the signing certificate; older builds send only a prefix
    ("87a38338387e0d42..."). A prefix of 16+ hex characters is compared as a prefix."""
    if not expected or "F076" not in signals:
        return None
    value = str(sig(signals["F076"]).value).lower().rstrip(".")
    if len(value) < 16 or any(c not in "0123456789abcdef" for c in value):
        return None
    return any(e.lower().startswith(value) for e in expected)
