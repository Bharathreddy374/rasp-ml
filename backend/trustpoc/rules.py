"""Stage 4: deterministic rules. Evidence tiers, the 5-level decision, and the action policy.

  Tier B  strong evidence a device-side check found, grouped in FAMILIES (root, instrumentation,
          virtual, app). Two families        -> Level 5
          one family                          -> Level 4
  Tier C  context: normal for developers and power users, meaningful in combination.
          developer class or 2+ Tier C        -> Level 3
          one Tier C                          -> Level 2
  none                                        -> Level 1

Tier A (cryptographic proof: replay, bad signature, wrong app) does not exist in this flow: the
collector payload is neither signed nor attested. That is why every decision carries
assurance = "unverified": Level 1 means "the data this device reported shows nothing wrong",
not "this device is proven genuine".
"""
from dataclasses import dataclass, field

LABELS = {1: "GENUINE", 2: "NORMAL", 3: "SUSPICIOUS", 4: "HIGH_RISK", 5: "CRITICAL"}

REASONS = {
    # Tier B: root
    "DV_ROOT_BINARY": "su binary reachable on the device.",
    "DV_ROOT_MANAGER_APP": "Root manager app installed (Magisk, KernelSU, APatch...).",
    "DV_ROOT_MOUNTS": "Root-framework mounts found in the mount table.",
    "DV_SYSTEM_RW": "System partition mounted read-write.",
    "DV_DANGEROUS_PROPS": "Build properties indicate a debuggable or insecure system.",
    "DV_SELINUX_NOT_ENFORCING": "SELinux is not enforcing.",
    # Tier B: instrumentation
    "RT_FRIDA": "Frida instrumentation artefacts in the app process.",
    "RT_TRACER_ATTACHED": "A debugger or tracer is attached to the app process.",
    "RT_XPOSED": "Xposed / LSPosed hooking framework present.",
    "RT_CODE_PATCHED": "Native code in memory differs from its file, or calls are redirected (inline / GOT / JNI hooks).",
    # Tier B: virtual and app
    "EM_EMULATOR": "Emulator or virtual device indicators.",
    "AP_CLONED_APP": "App runs from an unexpected data directory (clone or virtual space).",
    "AP_CERT_INCONSISTENT": "Installed signing certificate differs from the APK on disk, or the APK has no signing block.",
    "AP_CODE_MISMATCH": "Installed APK code does not match any configured release build.",
    "AP_CERT_MISMATCH": "App signing certificate is not one of the configured release certificates.",
    # Tier C
    "CX_DEVELOPER_OPTIONS": "Developer options enabled.",
    "CX_ADB_ENABLED": "USB or wireless debugging enabled.",
    "CX_TEST_KEYS": "OS build signed with test keys.",
    "CX_ACCESSIBILITY_SERVICE": "Third-party accessibility service enabled.",
    "CX_VPN": "VPN active.",
    "CX_PROBE_FAILURES": "Several probe groups failed on the device.",
    "CX_CLOCK_SKEW": "The phone's clock differs from the server's by more than 30 minutes.",
    "DV_UNMAPPED_ALERTS": "Other device probes raised alerts (signal IDs are stored with the session).",
    "HS_PATCH_REGRESSED": "Security patch level went backwards for this install.",
    "HS_OS_DOWNGRADE": "Android version went backwards for this install.",
    "HS_APP_VERSION_REGRESSED": "App version went backwards for this install.",
    "HS_BOOT_COUNT_RESET": "The phone's boot count went backwards since this install's last session.",
    "HS_UPTIME_INCONSISTENT": "The phone's uptime does not fit the time since this install's last session.",
    "HS_REINSTALLS": "The app was installed 3 or more times on this phone in 30 days.",
    "CX_HOSTING_IP": "Request came from a hosting / data-centre network.",
    "CX_TOR_EXIT": "Request came from a Tor exit node.",
    "CX_PROXY_HEADERS": "Request carried proxy headers.",
    "CX_COUNTRY_MISMATCH": "IP country differs from the SIM country.",
    "GR_FARM_CLUSTER": "This install belongs to a cluster of related installs that looks like a device farm.",
    # attestation and payload integrity
    "AT_SIGNATURE_INVALID": "The payload signature does not verify with the attested key.",
    "AT_NONCE_INVALID": "The request's nonce was not issued by this server, has expired, or was reused.",
    "AT_CHALLENGE_UNKNOWN": "The install key was created for a challenge this server did not issue (e.g. the server secret changed); the app makes a new key on its next send.",
    "AT_UNTRUSTED_CHAIN": "The key attestation chain does not lead to a Google root.",
    "AT_REVOKED": "A certificate in the attestation chain has been revoked by Google.",
    "AT_BOOTLOADER_UNLOCKED": "Hardware attestation reports an unlocked bootloader or unverified boot.",
    "AT_APP_CERT_MISMATCH": "The attested app signing certificate is not the release certificate.",
    "AT_PACKAGE_MISMATCH": "The attested package name is not this app.",
    "AT_KEY_SHARED": "The same attested key was used by more than one install.",
    "AT_BOOT_REGRESSED": "Verified boot was green for this install before and is not now.",
    "AT_SOFTWARE_KEY": "The install key is software-backed, not in secure hardware.",
    "AT_PROPS_MISMATCH": "The device's Android version or patch level disagrees with its hardware attestation.",
    "AT_LOCK_STATE_CHANGED": "The bootloader lock state changed since this install's last session.",
    # ML
    "ML_RISK": "The ML model scored a higher risk than the rules.",
}

# Tier B families: several hits in one family count once.
FAMILY = {
    "DV_ROOT_BINARY": "root", "DV_ROOT_MANAGER_APP": "root", "DV_ROOT_MOUNTS": "root",
    "DV_SYSTEM_RW": "root", "DV_SELINUX_NOT_ENFORCING": "root", "DV_DANGEROUS_PROPS": "root",
    "RT_FRIDA": "instrumentation", "RT_TRACER_ATTACHED": "instrumentation", "RT_XPOSED": "instrumentation",
    "RT_CODE_PATCHED": "instrumentation", "EM_EMULATOR": "virtual", "AP_CLONED_APP": "app",
    "AP_CERT_INCONSISTENT": "app", "AP_CODE_MISMATCH": "app", "AP_CERT_MISMATCH": "app",
    # attestation: a forged or replayed request counts once, however many checks fail
    "AT_SIGNATURE_INVALID": "integrity", "AT_NONCE_INVALID": "integrity", "AT_UNTRUSTED_CHAIN": "integrity",
    "AT_REVOKED": "integrity", "AT_KEY_SHARED": "integrity",
    "AT_BOOTLOADER_UNLOCKED": "root", "AT_BOOT_REGRESSED": "root",
    "AT_APP_CERT_MISMATCH": "app", "AT_PACKAGE_MISMATCH": "app",
}

ROOT_MANAGER_PACKAGES = {
    "com.topjohnwu.magisk", "io.github.huskydg.magisk", "io.github.vvb2060.magisk",
    "me.weishu.kernelsu", "me.bmax.apatch", "eu.chainfire.supersu",
    "com.noshufou.android.su", "com.koushikdutta.superuser", "com.kingroot.kinguser",
}


@dataclass
class Evidence:
    tier_b: list[str] = field(default_factory=list)
    tier_c: list[str] = field(default_factory=list)
    developer_class: bool = False

    def add(self, tier: str, code: str) -> None:
        bucket = {"B": self.tier_b, "C": self.tier_c}[tier]
        if code not in bucket:
            bucket.append(code)
        if code in ("CX_DEVELOPER_OPTIONS", "CX_ADB_ENABLED"):
            self.developer_class = True

    def codes(self) -> list[str]:
        return self.tier_b + self.tier_c


def _probe(probes: dict, name: str, default=None):
    p = probes.get(name)
    if not isinstance(p, dict) or p.get("status") != "ok":
        return default
    return p.get("v", default)


def evaluate_probes(probes: dict, ev: Evidence) -> None:
    """probes: name -> {"status": "ok"|"error", "v": value}, produced by normalize.normalize()."""
    # root
    if _probe(probes, "root_su_paths") or _probe(probes, "root_su_which") or _probe(probes, "root_su_exec"):
        ev.add("B", "DV_ROOT_BINARY")
    if set(_probe(probes, "root_manager_packages") or []) & ROOT_MANAGER_PACKAGES:
        ev.add("B", "DV_ROOT_MANAGER_APP")
    if _probe(probes, "root_magisk_mounts"):
        ev.add("B", "DV_ROOT_MOUNTS")
    if _probe(probes, "root_system_rw"):
        ev.add("B", "DV_SYSTEM_RW")
    if _probe(probes, "root_dangerous_props"):
        ev.add("B", "DV_DANGEROUS_PROPS")
    selinux = _probe(probes, "selinux_mode")
    if isinstance(selinux, str) and selinux and selinux.lower() != "enforcing":
        ev.add("B", "DV_SELINUX_NOT_ENFORCING")

    # instrumentation
    if _probe(probes, "rt_frida_maps") or _probe(probes, "rt_frida_threads") or _probe(probes, "rt_frida_port"):
        ev.add("B", "RT_FRIDA")
    if (_probe(probes, "rt_tracer_pid", 0) or 0) != 0 or _probe(probes, "rt_debugger_connected"):
        ev.add("B", "RT_TRACER_ATTACHED")
    if _probe(probes, "rt_xposed"):
        ev.add("B", "RT_XPOSED")
    if _probe(probes, "rt_code_patched"):
        ev.add("B", "RT_CODE_PATCHED")

    # emulator: two independent indicators
    if sum(bool(_probe(probes, n)) for n in
           ("emu_fingerprint", "emu_hardware", "emu_qemu_props", "emu_low_sensors", "emu_static_sensors")) >= 2:
        ev.add("B", "EM_EMULATOR")

    # app
    if _probe(probes, "app_data_dir_ok") is False:
        ev.add("B", "AP_CLONED_APP")
    if _probe(probes, "app_cert_inconsistent"):
        ev.add("B", "AP_CERT_INCONSISTENT")

    # context
    if _probe(probes, "ctx_developer_options"):
        ev.add("C", "CX_DEVELOPER_OPTIONS")
    if _probe(probes, "ctx_adb_enabled"):
        ev.add("C", "CX_ADB_ENABLED")
    if _probe(probes, "props_test_keys"):
        ev.add("C", "CX_TEST_KEYS")
    if _probe(probes, "ctx_accessibility_services"):
        ev.add("C", "CX_ACCESSIBILITY_SERVICE")
    if _probe(probes, "ctx_vpn"):
        ev.add("C", "CX_VPN")

    # probe health: context, never proof
    if sum(1 for p in probes.values() if isinstance(p, dict) and p.get("status") == "error") >= 2:
        ev.add("C", "CX_PROBE_FAILURES")


def decide_level(ev: Evidence) -> int:
    families = {FAMILY.get(c, c) for c in ev.tier_b}
    if len(families) >= 2:
        return 5
    if families:
        return 4
    if ev.developer_class or len(ev.tier_c) >= 2:
        return 3
    if ev.tier_c:
        return 2
    return 1


def reasons(ev: Evidence) -> list[dict]:
    return [{"code": c, "tier": t, "text": REASONS.get(c, c)}
            for t, codes in (("B", ev.tier_b), ("C", ev.tier_c)) for c in codes]


# Default action policy; the bank owns the real one.
POLICY = {
    "view_balance": {1: "allow", 2: "allow", 3: "allow", 4: "allow", 5: "block"},
    "login": {1: "allow", 2: "allow", 3: "step_up", 4: "step_up", 5: "block"},
    "transfer": {1: "allow", 2: "allow", 3: "step_up", 4: "block", 5: "block"},
    "add_payee": {1: "allow", 2: "step_up", 3: "step_up", 4: "block", 5: "block"},
    "high_value_transfer": {1: "allow", 2: "step_up", 3: "block", 4: "block", 5: "block"},
}


def policy_outcome(action: str, level: int) -> str:
    return POLICY.get(action, POLICY["transfer"]).get(level, "block")
