"""Deterministic rules, evidence tiers and the 5-level trust decision.

Mirrors the design doc (Sections 5.2, 7.1 and 7.6), simplified for the POC:
- Tier A (cryptographic / definitive)   -> Level 5
- 2+ Tier B hits from different families -> Level 5
- 1 Tier B family                        -> Level 4
- Developer class, or 2+ Tier C          -> Level 3
- 1 Tier C, reduced assurance, custom ROM -> Level 2
- otherwise                              -> Level 1
ML is shadow-only in v1 and never changes the level.
"""
from dataclasses import dataclass, field

LABELS = {1: "GENUINE", 2: "NORMAL", 3: "SUSPICIOUS", 4: "HIGH_RISK", 5: "CRITICAL"}

REASONS = {
    # Tier A
    "AT_PAYLOAD_SIGNATURE_INVALID": "Payload signature does not match the attested key.",
    "AT_NONCE_INVALID": "Nonce is unknown, expired or already used (possible replay).",
    "AT_NONCE_BINDING": "Nonce was issued for a different install or action.",
    "AT_CHAIN_INVALID": "Attestation certificate chain does not verify.",
    "AT_CHALLENGE_MISMATCH": "Attested challenge differs from the server nonce.",
    "AT_KEY_REVOKED": "Attestation key is on Google's revocation list.",
    "AP_SIGNATURE_MISMATCH": "App signing certificate is not the published release.",
    "AP_PACKAGE_MISMATCH": "App package name is not the expected one.",
    "AT_BOOT_FAILED": "Verified boot reports a failed or unverified OS.",
    # Tier B
    "DV_ROOT_BINARY": "su binary reachable on the device.",
    "DV_ROOT_MANAGER_APP": "Root manager app installed (Magisk, KernelSU, APatch...).",
    "DV_ROOT_MOUNTS": "Root-framework mounts found in the mount table.",
    "DV_SYSTEM_RW": "System partition mounted read-write.",
    "DV_DANGEROUS_PROPS": "Build properties indicate a debuggable or unlocked system.",
    "DV_SELINUX_NOT_ENFORCING": "SELinux is not enforcing.",
    "RT_FRIDA": "Frida instrumentation artefacts in the app process.",
    "RT_TRACER_ATTACHED": "A debugger or tracer is attached to the app process.",
    "RT_XPOSED": "Xposed / LSPosed hooking framework present.",
    "RT_CODE_PATCHED": "Native code in memory differs from its file, or calls are redirected (inline / GOT / JNI hooks).",
    "EM_EMULATOR": "Emulator or virtual device indicators.",
    "AP_CLONED_APP": "App runs from an unexpected data directory (clone or virtual space).",
    "AP_CERT_INCONSISTENT": "Installed signing certificate differs from the APK on disk, or the APK has no signing block.",
    "AP_CODE_MISMATCH": "Installed APK code does not match any configured release build.",
    # Tier C
    "CX_DEVELOPER_OPTIONS": "Developer options enabled.",
    "CX_ADB_ENABLED": "USB debugging enabled.",
    "CX_BOOTLOADER_UNLOCKED": "Bootloader unlocked (attested).",
    "CX_TEST_KEYS": "OS build signed with test keys.",
    "CX_ACCESSIBILITY_SERVICE": "Third-party accessibility service enabled.",
    "CX_VPN": "VPN active.",
    "CX_PROBE_FAILURES": "Several probes failed or were blocked.",
    "AT_SOFTWARE_ONLY": "Attestation is software-backed, not hardware-backed.",
    "AT_UNTRUSTED_ROOT": "Attestation chain does not end at a Google root; claims ignored.",
    "AT_NO_ATTESTATION": "No key attestation provided.",
    "AT_HARDWARE_REQUIRED": "Hardware-backed trusted attestation is required for this action.",
    "CX_CUSTOM_ROM": "Custom OS signed with its own key (self-signed verified boot).",
    "ML_RISK": "ML model scored a higher risk than the rules.",
    "AT_COUNTER_REGRESSED": "Request counter did not increase for this install.",
    "DV_UNMAPPED_ALERTS": "Other device probes raised alerts (see decision detail for signal IDs).",
    "DV_PROPS_VS_ATTESTATION": "Reported patch level or Android version differs from the hardware-attested value.",
    "HS_PATCH_REGRESSED": "Security patch level went backwards for this install.",
    "HS_VERIFIED_BOOT_REGRESSED": "Attested verified boot was green before and is not now.",
    "HS_BOOTLOADER_CHANGED": "Attested bootloader lock state changed for this install.",
    "HS_OS_DOWNGRADE": "Android version went backwards for this install.",
    "HS_APP_VERSION_REGRESSED": "App version went backwards for this install.",
}

# Tier B families: hits in the same family count once (design doc 4, redundancy groups)
FAMILY = {
    "DV_ROOT_BINARY": "root", "DV_ROOT_MANAGER_APP": "root", "DV_ROOT_MOUNTS": "root",
    "DV_SYSTEM_RW": "root", "DV_SELINUX_NOT_ENFORCING": "root", "DV_DANGEROUS_PROPS": "root",
    "RT_FRIDA": "instrumentation", "RT_TRACER_ATTACHED": "instrumentation", "RT_XPOSED": "instrumentation",
    "RT_CODE_PATCHED": "instrumentation",
    "EM_EMULATOR": "virtual", "AP_CLONED_APP": "app",
    "AP_CERT_INCONSISTENT": "app", "AP_CODE_MISMATCH": "app",
}

ROOT_MANAGER_PACKAGES = {
    "com.topjohnwu.magisk", "io.github.huskydg.magisk", "io.github.vvb2060.magisk",
    "me.weishu.kernelsu", "me.bmax.apatch", "eu.chainfire.supersu",
    "com.noshufou.android.su", "com.koushikdutta.superuser", "com.kingroot.kinguser",
}


@dataclass
class Evidence:
    tier_a: list[str] = field(default_factory=list)
    tier_b: list[str] = field(default_factory=list)
    tier_c: list[str] = field(default_factory=list)
    developer_class: bool = False
    custom_rom_class: bool = False
    reduced_assurance: bool = False

    def add(self, tier: str, code: str) -> None:
        bucket = {"A": self.tier_a, "B": self.tier_b, "C": self.tier_c}[tier]
        if code not in bucket:
            bucket.append(code)


def _probe(probes: dict, name: str, default=None):
    p = probes.get(name)
    if not isinstance(p, dict) or p.get("status") != "ok":
        return default
    return p.get("v", default)


def evaluate_probes(payload: dict, ev: Evidence) -> None:
    probes = payload.get("probes", {}) or {}

    # --- root (Tier B) ---
    if (_probe(probes, "root_su_paths") or []) or _probe(probes, "root_su_which"):
        ev.add("B", "DV_ROOT_BINARY")
    if set(_probe(probes, "root_manager_packages") or []) & ROOT_MANAGER_PACKAGES:
        ev.add("B", "DV_ROOT_MANAGER_APP")
    if _probe(probes, "root_magisk_mounts"):
        ev.add("B", "DV_ROOT_MOUNTS")
    if _probe(probes, "root_system_rw"):
        ev.add("B", "DV_SYSTEM_RW")
    if _probe(probes, "root_su_exec"):
        ev.add("B", "DV_ROOT_BINARY")
    if _probe(probes, "root_dangerous_props"):
        ev.add("B", "DV_DANGEROUS_PROPS")
    selinux = _probe(probes, "selinux_mode")
    if isinstance(selinux, str) and selinux and selinux.lower() != "enforcing":
        ev.add("B", "DV_SELINUX_NOT_ENFORCING")

    # --- instrumentation (Tier B) ---
    if (_probe(probes, "rt_frida_maps") or _probe(probes, "rt_frida_threads")
            or _probe(probes, "rt_frida_port")):
        ev.add("B", "RT_FRIDA")
    tracer = _probe(probes, "rt_tracer_pid", 0) or 0
    if tracer != 0 or _probe(probes, "rt_debugger_connected"):
        ev.add("B", "RT_TRACER_ATTACHED")
    if _probe(probes, "rt_xposed"):
        ev.add("B", "RT_XPOSED")
    if _probe(probes, "rt_code_patched"):
        ev.add("B", "RT_CODE_PATCHED")

    # --- emulator: need 2+ independent indicators (Tier B) ---
    emu_hits = sum(bool(_probe(probes, n)) for n in
                   ("emu_fingerprint", "emu_hardware", "emu_qemu_props", "emu_low_sensors", "emu_static_sensors"))
    if emu_hits >= 2:
        ev.add("B", "EM_EMULATOR")

    # --- app clone (Tier B) ---
    if _probe(probes, "app_data_dir_ok") is False:
        ev.add("B", "AP_CLONED_APP")
    if _probe(probes, "app_cert_inconsistent"):
        ev.add("B", "AP_CERT_INCONSISTENT")

    # --- context (Tier C) and developer class ---
    if _probe(probes, "ctx_developer_options"):
        ev.add("C", "CX_DEVELOPER_OPTIONS")
        ev.developer_class = True
    if _probe(probes, "ctx_adb_enabled"):
        ev.add("C", "CX_ADB_ENABLED")
        ev.developer_class = True
    if _probe(probes, "props_test_keys"):
        ev.add("C", "CX_TEST_KEYS")
    if _probe(probes, "ctx_accessibility_services"):
        ev.add("C", "CX_ACCESSIBILITY_SERVICE")
    if _probe(probes, "ctx_vpn"):
        ev.add("C", "CX_VPN")

    # --- probe health: context, never proof (design doc 4) ---
    failed = sum(1 for p in probes.values()
                 if isinstance(p, dict) and p.get("status") == "error")
    if failed >= 4:
        ev.add("C", "CX_PROBE_FAILURES")


def evaluate_attestation(att, payload: dict, cfg: dict, ev: Evidence) -> None:
    """att is an AttestationResult or None."""
    if att is None:
        ev.add("C", "AT_NO_ATTESTATION")
        ev.reduced_assurance = True
        return
    if not att.chain_valid:
        ev.add("A", "AT_CHAIN_INVALID")
        return
    if att.revoked:
        ev.add("A", "AT_KEY_REVOKED")

    # Claims are always read, but only trusted when the root is a Google root.
    if not att.root_trusted:
        ev.add("C", "AT_UNTRUSTED_ROOT")
        ev.reduced_assurance = True
    elif not att.hardware_backed:
        ev.add("C", "AT_SOFTWARE_ONLY")
        ev.reduced_assurance = True

    if att.trustworthy:
        if att.verified_boot_state in ("Unverified", "Failed"):
            ev.add("A", "AT_BOOT_FAILED")
        if att.device_locked is False:
            ev.add("C", "CX_BOOTLOADER_UNLOCKED")
            ev.developer_class = True
        elif att.verified_boot_state == "SelfSigned":
            ev.add("C", "CX_CUSTOM_ROM")
            ev.custom_rom_class = True

    # App identity: any source showing a non-expected digest means tampering.
    expected = {d.lower() for d in cfg.get("expected_cert_sha256", [])}
    pkg = cfg.get("expected_package")
    allowed = {pkg} if isinstance(pkg, str) else set(pkg or [])
    reported = {str(d).lower() for d in (payload.get("app", {}) or {}).get("cert_sha256", [])}
    attested = set(att.signing_digests)
    if expected:
        if (attested and not attested <= expected) or (reported and not reported <= expected):
            ev.add("A", "AP_SIGNATURE_MISMATCH")
    if allowed:
        names = set(att.package_names) | {(payload.get("app", {}) or {}).get("package")}
        names.discard(None)
        if names and not names <= allowed:
            ev.add("A", "AP_PACKAGE_MISMATCH")


def decide_level(ev: Evidence) -> int:
    if ev.tier_a:
        return 5
    families = {FAMILY.get(c, c) for c in ev.tier_b}
    if len(families) >= 2:
        return 5
    if families:
        return 4
    level = 1
    if ev.developer_class or len(ev.tier_c) >= 2:
        level = 3
    elif ev.tier_c or ev.reduced_assurance or ev.custom_rom_class:
        level = 2
    return level


def reasons(ev: Evidence) -> list[dict]:
    out = []
    for tier, codes in (("A", ev.tier_a), ("B", ev.tier_b), ("C", ev.tier_c)):
        for c in codes:
            out.append({"code": c, "tier": tier, "text": REASONS.get(c, c)})
    return out


# Proposed default action policy (design doc 7.7); the bank owns the real one.
POLICY = {
    "view_balance": {1: "allow", 2: "allow", 3: "allow", 4: "allow", 5: "block"},
    "login": {1: "allow", 2: "allow", 3: "step_up", 4: "step_up", 5: "block"},
    "transfer": {1: "allow", 2: "allow", 3: "step_up", 4: "block", 5: "block"},
    "add_payee": {1: "allow", 2: "step_up", 3: "step_up", 4: "block", 5: "block"},
    "high_value_transfer": {1: "allow", 2: "step_up", 3: "block", 4: "block", 5: "block"},
}


def policy_outcome(action: str, level: int) -> str:
    return POLICY.get(action, POLICY["transfer"]).get(level, "block")
