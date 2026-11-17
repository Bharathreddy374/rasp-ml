# Feature catalogue: what each signal is, how it is measured, how it varies by device

The system collects **370 signals** (F001–F370) in 12 groups. This page has two parts:

1. **By group:** what the signals mean, how each is measured (technique, API, file), what an attacker can and cannot fake, and how much the values vary between genuine devices.
2. **Full table:** every signal with its current status, whether it feeds the rules, and its device variance.

Status is taken from a **real scan of a genuine phone** (vivo I2221, Android 16), together with the code. All counts below are from that scan.

> **Current flow (`rasp_collect_v2`, see [BACKEND.md](BACKEND.md)).** The collector payload is not signed or attested, so **F001–F015 are not sent or verified** today; the attestation descriptions below apply to the archived signed flow ([archive/SIGNED_SCHEMA2.md](archive/SIGNED_SCHEMA2.md)). Of the backend-side signals, the server now computes **F081, F088, F299, F304, F305, F306, F309, F312, F314, F315, F329, F330–F332 and F339** from the request, each install's stored history and `config.json`. The other rows marked "Backend" are not computed yet. A rule's "Feeds rules" column shows whether a signal reaches the rules or the model.

| Status | Count | Meaning |
|---|---|---|
| Measured | 232 | Collected on the phone and sent typed in the signed payload. 23 of these come from the native library `libtrustprobe`. |
| Backend | 81 | Never reported by the phone. F001–F010 are read from the hardware attestation chain, 18 are computed from the request and history, and 47 are planned (they need GeoIP, TLS edge data, account IDs or a graph job). |
| Unknown | 57 | No measurement yet. Each is labelled with the reason. The backend treats unknown as *unknown*, never as clean. |

**Device variance** says how much a signal differs between *genuine* devices, which decides how it can be judged:

- **Low:** genuine devices all read the same (usually 0, false or "match"). A hit is meaningful on its own, so these feed the rules.
- **Medium:** differs by OEM, Android version or user settings. Use it as context, or combine it with other signals.
- **High:** differs by hardware model, OS build or the current state of the device (CPU load, temperature, motion). Never judge it alone. Compare it with the same model and Android version (the *cohort*), which is the ML model's job.
- **Per install / Fleet:** history of one install, or relationships across all devices.

> **Rule of thumb:** only Low-variance signals with a deterministic meaning raise the trust level directly. Everything else is ML input, sent so the model can learn per-model baselines.

---

## 1. Attestation (F001–F015)

**What:** hardware-backed proof of which device, which OS state and which app produced the request.

**How:**
1. For every request the app gets a one-time **nonce** from `/v1/nonce`.
2. It creates an EC key in **AndroidKeyStore** with `setAttestationChallenge(nonce)` and sends the key's **certificate chain**.
3. The backend (`trustpoc/attestation.py`) checks the chain:
   - it verifies certificate by certificate up to **Google's attestation roots**;
   - it checks every certificate serial against **Google's revocation list**;
   - it parses the **KeyDescription extension** (OID 1.3.6.1.4.1.11129.2.1.17).
4. The extension gives the security level (Software / TEE / StrongBox), verified boot state, bootloader lock, OS / vendor patch levels, package name, signing digests and the challenge.

| Signals | Meaning |
|---|---|
| F001–F002 | Chain valid; not revoked |
| F003 | Key in Software / TEE / StrongBox |
| F004–F005 | Verified boot state; bootloader locked |
| F006–F007 | OS and vendor patch level |
| F008–F009 | App signing digest and package name match (`config.json`) |
| F010 | Attested challenge equals the server nonce |
| F011–F015 | Play Integrity verdicts: **not integrated** (needs Play Console, a Cloud project and server-side token decoding) |

**Can it be faked?** Not by changing the app or rooting the phone: the chain is signed inside the TEE. Known weaknesses:
- **Leaked keyboxes:** stolen attestation keys. Covered by the revocation list and by F337 (how many installs share one intermediate certificate).
- **Software-only keystores:** these get "reduced assurance".

**Device variance: Medium.**
- Most phones from 2018 on have TEE keys; StrongBox is rarer.
- Patch levels differ by OEM.
- Some low-end or old devices have only software attestation.
- Emulators have an untrusted, software chain. The emulator test confirmed this: "root UNTRUSTED, Software, boot Unverified, unlocked".

## 2. Device / static (F016–F075)

**What:** OS build properties, SELinux, root artefacts, mount tables and the kernel.

**How:**
- **Build properties:** `android.os.Build` and `SystemProperties` (`ro.debuggable`, `ro.secure`, `ro.build.tags/type`, fingerprint, `ro.boot.verifiedbootstate`, `ro.boot.flash.locked`). F026 compares `Build` fields with the properties they come from; spoofers usually change only one side.
- **SELinux:** `/sys/fs/selinux/enforce`.
- **Root artefacts:** su paths checked three ways:
  - Java `File` (F037)
  - libc `access()` (F038)
  - a **raw `svc` syscall from native code** that skips libc (F039)

  F040 counts disagreements between them; a disagreement means a hook is hiding files. Also root manager packages (Magisk, KernelSU, APatch), Magisk files, setuid binaries (F054) and the `su` exec test.
- **Mounts:** `/proc/self/mounts` and `/proc/self/mountinfo`. Root hiders unmount entries from the app's namespace, which leaves gaps (F055) and mismatched views (F066). Module overlays appear as mounts over system code (F061). F050/F051/F065 match the `/`, `/system` and `/vendor` mount points **exactly**; rw mounts *under* `/vendor` (firmware, dsp) are normal.
- **Kernel:** version, cmdline, `/proc/modules` and `kallsyms` (if readable), KernelSU / APatch probes, Zygisk in maps.

**Device variance:**

| Sub-group | Variance | Why |
|---|---|---|
| Build properties (F016–F030) | High | Fingerprints, OEM names and custom-ROM keywords differ by vendor. |
| SELinux (F031–F036) | Low | Enforcing on every certified device. Policy details are not visible to apps (F034–F036 unknown). |
| Root artefacts (F037–F054) | Low | Clean on every stock device. Newer Android hides more from apps: on Android 16, F054 (listing `/system/bin`) and F048 (`/proc/net/unix`) are blocked, so they are unknown. |
| Mounts and kernel (F055–F075) | High | Mount tables differ a lot between OEMs and Android versions. Fixed in testing: Android 11+ mounts `/data_mirror`, so the word "mirror" is no longer treated as Magisk. Stock Android creates `/data/adb`, so only Magisk / KernelSU / APatch content inside it counts. |

## 3. App integrity (F076–F115)

**What:** is this the genuine APK, installed normally, running in its own sandbox?

**How:**
- **Signing:**
  - certificate from PackageManager vs the certificate parsed from the APK file on disk (F078);
  - signature schemes and APK Signing Block read directly from the file (F079, F083);
  - signing digest also compared on the backend (F081).
- **APK contents (F084–F092):** the app reads the zip central directory of its installed APK and reports SHA-256 digests of DEX, native-library and asset entries, plus resources and manifest CRCs (no decompression). On the backend:
  - `tools/apk_manifest.py` computes the same digests from a release APK;
  - the result goes into `config.json` → `release_manifests`;
  - any APK that matches no release raises `AP_CODE_MISMATCH`.
- **Install origin:** installer package, Play or not, paths, split APKs, version vs server.
- **Clone / virtual space:**
  - UID, process name vs package (F109);
  - data directory compared after resolving symlinks (F108; `/data/user/0` links to `/data/data`);
  - host-app classes and frames in the stack;
  - dual-app and work-profile flags.
- **Dynamically loaded code:** non-standard class loaders in the chain (F110), in-memory DEX (F111), native libraries mapped from writable or foreign paths (F115).

**Device variance:**

| Sub-group | Variance | Why |
|---|---|---|
| Signing and APK contents (F076–F093) | Low | The same APK is identical everywhere. |
| Install origin (F094–F101) | Medium | Play, OEM stores and sideloading all differ. |
| Clone and dynamic code (F102–F115) | Medium | **Watch OEM "dual app" features** (Xiaomi Dual Apps, Samsung Dual Messenger, vivo App Clone). They run genuine apps in a second user or profile, which looks like a clone. That is why clone evidence is one family in the rules, never Level 5 on its own. |

## 4. Runtime / hooking (F116–F175)

**What:** is anything attached to, injected into, or patching the app process *right now*?

**How:**
- **Debugger:**
  - `TracerPid` in `/proc/self/status`, ptrace self-test;
  - JDWP / `Debug.isDebuggerConnected()`, gdb / lldb server processes.
- **Frida:**
  - agent and gadget in `/proc/self/maps` (F124/F125);
  - its threads `gum-js-loop`, `gmain`, `gdbus` (F126–F128);
  - ports 27042+ (F129/F130);
  - a **protocol handshake** that works even when the server is renamed (F131): Frida 15+ accepts a WebSocket upgrade on `/ws` with "101 Switching Protocols", and older Frida answers D-Bus `AUTH` with "REJECTED";
  - server files (F132), memfd agents (excluding ART's `jit-cache`) (F133), injector traces in maps / fds (F137).
- **Xposed / LSPosed / Zygisk:**
  - bridge classes and stack frames, manager apps;
  - hook classes loadable from the app's class loaders (F171);
  - a Riru-style native-bridge property (F145);
  - Java methods suddenly flagged `native` (F166).
- **Native hooks (native library `app/src/main/cpp/trustprobe.c`):**
  - **F146–F155:** the first 16 bytes of `open`, `read`, `stat`, `access`, `fopen`, `ptrace`, `dlopen`, `mmap` and `syscall` in memory, compared with the **same bytes in the library file they were mapped from** (path and offset from `/proc/self/maps`). Inline hooks patch memory, not the file.
  - **F156/F157:** the app library's GOT entries compared with `dlsym(libc, …)`, which catches PLT/GOT hooks.
  - **F159:** `getpid`, `getuid` and file checks through libc compared with raw syscalls.
  - **F163:** every JNIEnv function pointer must point into `libart`.
- **ART internals (F160–F162, F164, F165, F168, F169):** **unknown.** ArtMethod layouts change with every Android version, so these need a version-aware design.
- **Call-stack / UI tampering (F170–F175):** foreign stack frames and hidden classes are measured. Accessibility injection, tapjacking overlays and `FLAG_SECURE` need hooks in the app's own screens (unknown).

**Device variance: Low.** A genuine phone reads 0 or false on all of these. The only variation is the CPU architecture (arm64 on phones, x86_64 on emulators), which the native library handles.

**Verified on a rooted emulator with Frida 17.26.3** injecting a root-hiding hook:
- The 4 hooked libc functions were flagged with 5–6 bytes patched each, and the unhooked ones read 0.
- Frida was detected by its agent, threads, ports, WebSocket handshake, server file and RWX memory.
- The result was Level 5 with `RT_FRIDA` and `RT_CODE_PATCHED`, and the ML instrumentation score was 1.0.

## 5. Memory / procfs (F176–F205)

**What:** the *shape* of the process, which injected code changes even when it is renamed.

**How:** summary statistics from `/proc/self/maps`, `/proc/self/status`, `/proc/self/task/*` and `/proc/self/fd`:
- region counts, anonymous executable and RWX regions, deleted mappings;
- libraries outside the system / vendor / product / apex / app folders (F184);
- memfd regions; seccomp mode; capabilities;
- thread counts, names and entropy, real-time threads;
- open sockets, pipes, ashmem, temp files, `/proc/self/mem` handles.

**Device variance: High.** Layouts depend on the Android and ART version, OEM libraries and app state. For example, on a genuine phone:
- 75 deleted mappings is normal;
- `NoNewPrivs` = 0 is normal for every app, because zygote installs seccomp without it.

These signals are recorded for per-model comparison. Only the definitive ones (RWX regions, Frida thread names, injected libraries) are alerts.

## 6. Timing side-channels (F206–F230)

**What:** hooks make the calls they intercept slower.

**How:**
- **Hidden vs control ratios (F206–F208):** median `open`, `access` and `stat` latency on paths root hiders target (`/system/xbin/su`, `/data/adb/magisk`, …), divided by the latency on random missing paths in the same folders. 32 interleaved trials each. About 1.0 on a clean device; the genuine phone measured 1.00–1.01.
- **Absolute latencies:**
  - `readlink`, `open`, `pread`, thread start;
  - native: libc vs raw `getpid` (F210/F213), JNI round-trip (F215), `mmap` (F219), `dlsym` (F220);
  - reflection;
  - attestation key generation (F223/F224);
  - total scan time (F221).
- **Clock behaviour:** drift, jitter, resolution, loop calibration, cache-timing variance. Virtualised clocks are noisier.

**Device variance: High.** Absolute numbers depend on CPU, governor, thermal state and battery saver. Ratios (F206–F208, F210) are far more stable than absolute numbers. All timing signals are ML inputs, never rules on their own.

## 7. Sensor and touch (F231–F270)

**What:** real hardware has physics; emulators and replayed sensors do not.

**How:**
- Accelerometer, gyroscope and magnetometer are sampled for **1.5 s** at `SENSOR_DELAY_GAME`.
- **Only summary statistics leave the phone, never raw samples:**
  - per-axis noise (standard deviation), kurtosis, gravity-magnitude error;
  - spectral flatness and dominant frequency (DFT);
  - identical-sample counts;
  - accelerometer / gyroscope correlation;
  - 8–12 Hz hand-tremor band energy;
  - timestamp jitter, actual sample rate, ADC quantisation step;
  - magnetic field strength;
  - sensor count and vendor, declared power draw;
  - battery level, temperature and charging state.
- **Touch dynamics (F259–F266): unknown.** They need capture inside the app's own screens.

**Device variance: High** (sensor chips, rates and tablets without a gyroscope or magnetometer).

| | Genuine phone | Emulator |
|---|---|---|
| Accelerometer noise | 0.029 m/s² | exactly 0 |
| Gravity error | 0.04 m/s² | |
| Magnetic field | 38 µT | |
| Sample rate | 51 Hz | |
| Identical samples | | 75 of 75 |

"Exactly 0 noise" and "most samples identical" feed the emulator rule. Everything else is ML input.

> Privacy: sensor and touch statistics can be considered behavioural data. Confirm with your DPO before enabling them in production.

## 8. Risky context (F271–F285)

**What:** settings that are normal for power users but enable fraud in combination.

**How:**
- accessibility services, especially from non-system apps (F273);
- overlay permissions, extra displays such as casting or mirroring (F276), media projection;
- developer options, USB / wireless debugging, unknown sources, VPN;
- device-admin apps (F283), notification listeners, unknown input methods.

**Device variance: Medium.** These depend on the user, not the hardware. Developers, enterprise MDM users and accessibility users have legitimate reasons. These are Tier C (context): they lead to step-up, never a block.

## 9–11. Network, history and graph (F286–F350): backend only

**What:** facts the phone cannot know or fake.

**How:** `trustpoc/server_signals.py` computes them from the request and from each install's history.

| Computed today | What it is |
|---|---|
| F299 | User-Agent vs signed device block |
| F304 | IP changes per session |
| F305 | Request-timing regularity |
| F306–F309, F312, F314, F315 | Patch / boot / bootloader / fingerprint / OS / app-version regressions |
| F329 | Time since first seen |
| F330–F332 | Risk history over 30 days |
| F337 | Installs sharing one attestation intermediate (leaked-keybox farms) |
| F339 | Installs per /24 network |
| F025, F088 | Attestation and APK-manifest cross-checks |

**Planned (47):** they need data this service does not have yet: GeoIP/ASN databases, TLS fingerprints from the edge proxy, bank account and payee IDs, and an offline graph job.

**Note:** history is kept **in memory** and resets on restart. Production needs it in Redis or Postgres.

**Device variance:** network data is per user and connection; history is per install; graph is fleet-wide.

## 12. Probe health (F351–F370)

**What:** can the telemetry itself be trusted?

**How:**
- **On the phone:**
  - failed probe groups (F351);
  - reads the OS refused (F353);
  - missing signals (F356);
  - the native library's own code compared with its file (F360);
  - where the native library was loaded from (F368).
- **On the backend, every request:** counter (F363), signature (F364), payload age (F365).
- **Planned:** canaries, SDK self-hash, certificate pinning.

**Device variance: Medium.** SELinux gets stricter with each Android version, so blocked reads rise on newer phones. A failed or blocked probe is **unknown, never clean**.

---

## How signals become a decision

1. **Rules** (`trustpoc/rules.py`) use evidence tiers:
   - **Tier A** (cryptographic: replay, bad signature, wrong app, failed boot) → Level 5.
   - **Two Tier B families** (root, instrumentation, emulator, app tamper) → Level 5.
   - **One Tier B family** → Level 4.
   - **Developer class or 2+ Tier C** → Level 3.
   - **1 Tier C or reduced assurance** → Level 2.
2. **ML** (`trustpoc/ml.py`): 4 gradient-boosted threat heads plus an Isolation Forest. The final level is `max(rules, ML)`: ML can raise risk but never lower hard evidence. **The models are trained on synthetic data**, so their scores are not real accuracy until they are retrained on collected sessions (`data/sessions.jsonl`, `device_assessments` table).
3. **Policy** maps level × action to allow, step-up or block, e.g. `transfer` at Level 4 → block. The decision is returned as a signed ES256 JWS that the bank backend verifies.

---

## Full signal table

Generated from the code and a real phone scan (vivo I2221, Android 16).

| ID | Signal | Status | Feeds rules | Varies by device |
|---|---|---|---|---|
| F001 | `attest_chain_valid` | Backend (from attestation chain) | Yes | Medium |
| F002 | `attest_cert_revoked` | Backend (from attestation chain) | Yes | Medium |
| F003 | `attest_security_level` | Backend (from attestation chain) | Yes | Medium |
| F004 | `attest_verified_boot_state` | Backend (from attestation chain) | Yes | Medium |
| F005 | `attest_device_locked` | Backend (from attestation chain) | Yes | Medium |
| F006 | `attest_os_patch_level` | Backend (from attestation chain) | Yes | Medium |
| F007 | `attest_vendor_patch_level` | Backend (from attestation chain) | Yes | Medium |
| F008 | `attest_app_cert_digest_match` | Backend (from attestation chain) | Yes | Medium |
| F009 | `attest_package_name_match` | Backend (from attestation chain) | Yes | Medium |
| F010 | `attest_nonce_valid` | Backend (from attestation chain) | Yes | Medium |
| F011 | `pi_device_verdict` | Unknown: Play Integrity (not integrated) |  | Medium |
| F012 | `pi_app_verdict` | Unknown: Play Integrity (not integrated) |  | Medium |
| F013 | `pi_licensing` | Unknown: Play Integrity (not integrated) |  | Medium |
| F014 | `pi_recent_device_activity` | Unknown: Play Integrity (not integrated) |  | Medium |
| F015 | `pi_app_access_risk` | Unknown: Play Integrity (not integrated) |  | Medium |
| F016 | `ro_debuggable` | Measured | Yes | High |
| F017 | `ro_secure` | Measured | Yes | High |
| F018 | `build_tags_test_keys` | Measured | Yes | High |
| F019 | `build_type_userdebug` | Measured |  | High |
| F020 | `fingerprint_model_consistent` | Measured |  | High |
| F021 | `fingerprint_soc_consistent` | Measured |  | High |
| F022 | `boot_verifiedbootstate_prop` | Measured |  | High |
| F023 | `boot_flash_locked_prop` | Measured |  | High |
| F024 | `boot_vbmeta_digest_known` | Measured |  | High |
| F025 | `prop_vs_attest_mismatch` | Backend | Yes | High |
| F026 | `prop_vs_build_mismatch` | Measured | Yes | High |
| F027 | `resetprop_trace_score` | Measured |  | High |
| F028 | `custom_rom_fingerprint` | Measured |  | High |
| F029 | `oem_fingerprint_allowlisted` | Measured |  | High |
| F030 | `build_date_vs_patch_gap` | Measured |  | High |
| F031 | `selinux_mode` | Measured | Yes | Low |
| F032 | `selinux_policy_version` | Measured |  | Low |
| F033 | `selinux_context_of_app` | Measured |  | Low |
| F034 | `selinux_permissive_domains_count` | Unknown: not visible to apps |  | Low |
| F035 | `sepolicy_modified_hash` | Unknown: not visible to apps |  | Low |
| F036 | `selinux_denials_unexpected` | Unknown: not visible to apps |  | Low |
| F037 | `su_path_java` | Measured | Yes | Low |
| F038 | `su_path_libc` | Measured | Yes | Low |
| F039 | `su_path_syscall` | Measured (native) | Yes | Low |
| F040 | `su_path_disagreement` | Measured (native) | Yes | Low |
| F041 | `su_in_PATH` | Measured | Yes | Low |
| F042 | `busybox_present` | Measured |  | Low |
| F043 | `magisk_pkg_present` | Measured | Yes | Low |
| F044 | `magisk_pkg_signature_hash` | Measured |  | Low |
| F045 | `kernelsu_manager_present` | Measured | Yes | Low |
| F046 | `apatch_manager_present` | Measured | Yes | Low |
| F047 | `magisk_files_data_adb` | Measured | Yes | Low |
| F048 | `magisk_socket_abstract` | Unknown: blocked on newer Android |  | Low |
| F049 | `root_manager_apps_count` | Measured |  | Low |
| F050 | `rw_system_mount` | Measured | Yes | Low |
| F051 | `rw_vendor_mount` | Measured | Yes | Low |
| F052 | `test_keys_ota_certs` | Measured |  | Low |
| F053 | `su_exec_result` | Measured | Yes | Low |
| F054 | `setuid_binaries_count` | Unknown: blocked on newer Android | Yes | Low |
| F055 | `mountinfo_id_gaps` | Measured |  | High |
| F056 | `mountinfo_count_vs_cohort` | Measured |  | High |
| F057 | `overlay_on_system` | Measured |  | High |
| F058 | `tmpfs_on_system_paths` | Measured |  | High |
| F059 | `debug_ramdisk_mount` | Measured |  | High |
| F060 | `magisk_mount_names` | Measured | Yes | High |
| F061 | `bind_mounts_on_system_libs` | Measured |  | High |
| F062 | `mount_ns_inode_differs` | Unknown: not visible to apps |  | High |
| F063 | `system_partition_ro` | Measured |  | High |
| F064 | `dm_verity_enabled` | Measured |  | High |
| F065 | `vendor_partition_ro` | Measured |  | High |
| F066 | `proc_mounts_vs_mountinfo_diff` | Measured |  | High |
| F067 | `kernel_version_cohort_match` | Measured |  | High |
| F068 | `kernel_cmdline_flags` | Measured |  | High |
| F069 | `lsmod_visible_modules` | Measured |  | High |
| F070 | `kmsg_readable` | Measured |  | High |
| F071 | `kallsyms_readable` | Measured |  | High |
| F072 | `proc_modules_unusual` | Unknown: blocked on newer Android |  | High |
| F073 | `ksu_syscall_probe` | Measured |  | High |
| F074 | `apatch_probe` | Measured |  | High |
| F075 | `zygisk_in_zygote_maps` | Measured |  | High |
| F076 | `apk_cert_sha256_pm` | Measured |  | Low |
| F077 | `apk_cert_sha256_parsed` | Measured |  | Low |
| F078 | `apk_cert_two_source_mismatch` | Measured | Yes | Low |
| F079 | `signing_scheme_version` | Measured |  | Low |
| F080 | `v1_only_signature` | Measured |  | Low |
| F081 | `cert_in_allowlist` | Backend |  | Low |
| F082 | `signing_cert_count` | Measured |  | Low |
| F083 | `apk_sig_block_present` | Measured | Yes | Low |
| F084 | `dex_hash_mismatch_count` | Measured | Yes | Low |
| F085 | `dex_extra_files` | Measured |  | Low |
| F086 | `so_hash_mismatch_count` | Measured | Yes | Low |
| F087 | `so_extra_libs` | Measured |  | Low |
| F088 | `so_missing_libs` | Backend | Yes | Low |
| F089 | `apk_size_vs_manifest` | Measured |  | Low |
| F090 | `resources_arsc_hash` | Measured | Yes | Low |
| F091 | `manifest_hash` | Measured | Yes | Low |
| F092 | `assets_hash_mismatch` | Measured | Yes | Low |
| F093 | `oat_vdex_unexpected` | Unknown: needs per-model baseline |  | Low |
| F094 | `installer_package` | Measured |  | Medium |
| F095 | `installer_is_play` | Measured |  | Medium |
| F096 | `install_time_vs_update` | Measured |  | Medium |
| F097 | `sourceDir_path_shape` | Measured |  | Medium |
| F098 | `dataDir_path_shape` | Measured | Yes | Medium |
| F099 | `apk_in_unusual_dir` | Measured | Yes | Medium |
| F100 | `split_apks_unexpected` | Measured |  | Medium |
| F101 | `version_code_vs_server` | Measured |  | Medium |
| F102 | `uid_vs_expected` | Measured |  | Medium |
| F103 | `pid_ns_unusual` | Unknown: not visible to apps |  | Medium |
| F104 | `foreign_pkgs_in_maps` | Measured |  | Medium |
| F105 | `host_app_classes_in_stack` | Measured |  | Medium |
| F106 | `dual_app_flag` | Measured |  | Medium |
| F107 | `work_profile_flag` | Measured |  | Medium |
| F108 | `virtual_space_markers` | Measured | Yes | Medium |
| F109 | `process_name_mismatch` | Measured | Yes | Medium |
| F110 | `dexclassloader_instances` | Measured |  | Medium |
| F111 | `inmemory_dex_loaders` | Measured |  | Medium |
| F112 | `classloader_chain_length` | Measured |  | Medium |
| F113 | `unknown_dex_in_maps` | Measured |  | Medium |
| F114 | `native_lib_loaded_from_tmp` | Measured |  | Medium |
| F115 | `dlopen_unknown_paths` | Measured | Yes | Medium |
| F116 | `tracer_pid` | Measured | Yes | Low |
| F117 | `ptrace_traceme_fails` | Measured | Yes | Low |
| F118 | `jdwp_active` | Measured | Yes | Low |
| F119 | `debuggable_flag` | Measured |  | Low |
| F120 | `wait_for_debugger` | Measured |  | Low |
| F121 | `debug_connected` | Measured | Yes | Low |
| F122 | `gdbserver_proc` | Measured |  | Low |
| F123 | `lldb_server_proc` | Measured |  | Low |
| F124 | `frida_agent_in_maps` | Measured | Yes | Low |
| F125 | `frida_gadget_in_maps` | Measured | Yes | Low |
| F126 | `gum_js_loop_thread` | Measured | Yes | Low |
| F127 | `gmain_thread` | Measured | Yes | Low |
| F128 | `gdbus_thread` | Measured | Yes | Low |
| F129 | `frida_default_port_open` | Measured | Yes | Low |
| F130 | `frida_port_scan_any` | Measured | Yes | Low |
| F131 | `frida_dbus_handshake` | Measured | Yes | Low |
| F132 | `frida_server_file_names` | Measured | Yes | Low |
| F133 | `frida_memfd_mappings` | Measured | Yes | Low |
| F134 | `frida_tmp_artifacts` | Measured |  | Low |
| F135 | `frida_named_pipes` | Measured |  | Low |
| F136 | `frida_stack_signature` | Unknown: native (ART internals) |  | Low |
| F137 | `frida_injector_marks` | Measured | Yes | Low |
| F138 | `xposed_bridge_class` | Measured | Yes | Low |
| F139 | `xposed_stack_frames` | Measured | Yes | Low |
| F140 | `lsposed_manager_present` | Measured | Yes | Low |
| F141 | `lsposed_classes_loaded` | Measured | Yes | Low |
| F142 | `riru_zygisk_libs` | Measured | Yes | Low |
| F143 | `edxposed_markers` | Measured | Yes | Low |
| F144 | `substrate_cydia_markers` | Measured |  | Low |
| F145 | `hook_framework_props` | Measured | Yes | Low |
| F146 | `open` | Measured (native) | Yes | Low |
| F147 | `read` | Measured (native) | Yes | Low |
| F148 | `stat` | Measured (native) | Yes | Low |
| F149 | `access` | Measured (native) | Yes | Low |
| F150 | `fopen` | Measured (native) | Yes | Low |
| F151 | `ptrace` | Measured (native) | Yes | Low |
| F152 | `dlopen` | Measured (native) | Yes | Low |
| F153 | `mmap` | Measured (native) | Yes | Low |
| F154 | `syscall` | Measured (native) | Yes | Low |
| F155 | `prologue_diff_count_total` | Measured (native) | Yes | Low |
| F156 | `plt_got_mismatch_count` | Measured (native) | Yes | Low |
| F157 | `got_outside_module_targets` | Measured (native) | Yes | Low |
| F158 | `jump_trampoline_in_anon_rx` | Measured |  | Low |
| F159 | `svc_vs_libc_result_diff` | Measured (native) | Yes | Low |
| F160 | `artmethod_entry_out_of_range` | Unknown: native (ART internals) |  | Low |
| F161 | `critical_method_entry_diff` | Unknown: native (ART internals) |  | Low |
| F162 | `jni_register_natives_changed` | Unknown: native (ART internals) |  | Low |
| F163 | `jni_function_table_diff` | Measured (native) | Yes | Low |
| F164 | `vtable_changed` | Unknown: native (ART internals) |  | Low |
| F165 | `interpreter_bridge_forced` | Unknown: native (ART internals) |  | Low |
| F166 | `native_flag_on_java_method` | Measured | Yes | Low |
| F167 | `method_count_vs_manifest` | Unknown: needs release manifest |  | Low |
| F168 | `art_runtime_flags_odd` | Unknown: native (ART internals) |  | Low |
| F169 | `jit_cache_unexpected` | Unknown: native (ART internals) |  | Low |
| F170 | `stack_trace_foreign_frames` | Measured |  | Low |
| F171 | `class_lookup_hidden_classes` | Measured | Yes | Low |
| F172 | `reflection_on_sensitive_apis` | Unknown: native (ART internals) |  | Low |
| F173 | `accessibility_service_injection` | Unknown: needs in-app UI capture |  | Low |
| F174 | `overlay_over_app_window` | Unknown: needs in-app UI capture |  | Low |
| F175 | `window_flag_secure_cleared` | Unknown: needs in-app UI capture |  | Low |
| F176 | `maps_region_count` | Measured |  | High |
| F177 | `maps_file_backed_ratio` | Measured |  | High |
| F178 | `anon_exec_bytes` | Measured |  | High |
| F179 | `anon_rwx_regions` | Measured |  | High |
| F180 | `deleted_mappings_count` | Measured |  | High |
| F181 | `distinct_backing_files` | Measured |  | High |
| F182 | `region_size_entropy` | Measured |  | High |
| F183 | `jaccard_vs_cohort_files` | Unknown: needs per-model baseline |  | High |
| F184 | `unknown_so_count` | Measured |  | High |
| F185 | `memfd_mappings` | Measured |  | High |
| F186 | `ashmem_exec_maps` | Measured |  | High |
| F187 | `vdso_vvar_odd` | Measured |  | High |
| F188 | `seccomp_mode` | Measured |  | High |
| F189 | `cap_effective` | Measured |  | High |
| F190 | `cap_bounding_diff` | Measured |  | High |
| F191 | `nonewprivs` | Measured |  | High |
| F192 | `threads_count` | Measured |  | High |
| F193 | `vmrss_vs_cohort` | Measured |  | High |
| F194 | `thread_name_entropy` | Measured |  | High |
| F195 | `unnamed_threads_count` | Measured |  | High |
| F196 | `suspicious_thread_names` | Measured | Yes | High |
| F197 | `threads_vs_cohort` | Unknown: needs per-model baseline |  | High |
| F198 | `thread_start_addrs_anon` | Unknown: native (ART internals) |  | High |
| F199 | `thread_priority_odd` | Measured |  | High |
| F200 | `fd_count` | Measured |  | High |
| F201 | `fd_sockets_unusual` | Measured |  | High |
| F202 | `fd_pipes_unusual` | Measured |  | High |
| F203 | `fd_ashmem` | Measured |  | High |
| F204 | `fd_to_tmp_files` | Measured |  | High |
| F205 | `fd_to_proc_mem` | Measured |  | High |
| F206 | `openat_hidden_vs_control_ratio` | Measured |  | High |
| F207 | `access_hidden_vs_control_ratio` | Measured |  | High |
| F208 | `stat_hidden_vs_control_ratio` | Measured |  | High |
| F209 | `readlink_proc_exe_ns` | Measured |  | High |
| F210 | `getpid_libc_vs_syscall_ratio` | Measured (native) |  | High |
| F211 | `libc_open_latency_ns` | Measured |  | High |
| F212 | `libc_read_latency_ns` | Measured |  | High |
| F213 | `syscall_svc_latency_ns` | Measured (native) |  | High |
| F214 | `openat_hidden_median_ns` | Measured |  | High |
| F215 | `jni_roundtrip_ns` | Measured (native) |  | High |
| F216 | `jni_roundtrip_zscore` | Unknown: needs per-model baseline |  | High |
| F217 | `java_reflection_call_ns` | Measured |  | High |
| F218 | `thread_start_latency_ns` | Measured |  | High |
| F219 | `mmap_latency_ns` | Measured (native) |  | High |
| F220 | `dlsym_latency_ns` | Measured (native) |  | High |
| F221 | `probe_total_duration_ms` | Measured |  | High |
| F222 | `probe_duration_zscore` | Unknown: needs per-model baseline |  | High |
| F223 | `attestation_latency_ms` | Measured |  | High |
| F224 | `key_gen_latency_ms` | Measured |  | High |
| F225 | `pi_token_latency_ms` | Unknown: Play Integrity (not integrated) |  | High |
| F226 | `monotonic_vs_wall_drift` | Measured |  | High |
| F227 | `clock_gettime_jitter` | Measured |  | High |
| F228 | `timer_resolution_ns` | Measured |  | High |
| F229 | `loop_calibration_ns` | Measured |  | High |
| F230 | `cache_timing_variance` | Measured |  | High |
| F231 | `accel_std_x` | Measured | Yes | High |
| F232 | `accel_std_y` | Measured | Yes | High |
| F233 | `accel_std_z` | Measured | Yes | High |
| F234 | `accel_kurtosis_x` | Measured |  | High |
| F235 | `accel_kurtosis_y` | Measured |  | High |
| F236 | `accel_kurtosis_z` | Measured |  | High |
| F237 | `gravity_magnitude_error` | Measured |  | High |
| F238 | `accel_spectral_flatness` | Measured |  | High |
| F239 | `accel_dominant_freq_hz` | Measured |  | High |
| F240 | `accel_repeat_sample_count` | Measured | Yes | High |
| F241 | `gyro_std_x` | Measured | Yes | High |
| F242 | `gyro_std_y` | Measured | Yes | High |
| F243 | `gyro_std_z` | Measured | Yes | High |
| F244 | `gyro_bias_estimate` | Measured |  | High |
| F245 | `gyro_spectral_flatness` | Measured |  | High |
| F246 | `gyro_dominant_freq_hz` | Measured |  | High |
| F247 | `gyro_repeat_sample_count` | Measured | Yes | High |
| F248 | `gyro_zero_rate_noise` | Measured |  | High |
| F249 | `accel_gyro_xcorr_lag0` | Measured |  | High |
| F250 | `accel_mag_consistency` | Measured |  | High |
| F251 | `tremor_band_energy_8_12hz` | Measured |  | High |
| F252 | `sensor_timestamp_jitter_cv` | Measured |  | High |
| F253 | `sensor_sample_rate_actual` | Measured |  | High |
| F254 | `sensor_quantization_step` | Measured |  | High |
| F255 | `sensor_count` | Measured | Yes | High |
| F256 | `sensor_vendor_known` | Measured |  | High |
| F257 | `sensor_vendor_vs_model` | Unknown: needs per-model baseline |  | High |
| F258 | `sensor_power_draw_plausible` | Measured |  | High |
| F259 | `touch_pressure_mean` | Unknown: needs in-app UI capture |  | High |
| F260 | `touch_pressure_var` | Unknown: needs in-app UI capture |  | High |
| F261 | `touch_size_mean` | Unknown: needs in-app UI capture |  | High |
| F262 | `touch_inter_event_ms_cv` | Unknown: needs in-app UI capture |  | High |
| F263 | `touch_velocity_profile` | Unknown: needs in-app UI capture |  | High |
| F264 | `touch_down_up_ms` | Unknown: needs in-app UI capture |  | High |
| F265 | `touch_pos_entropy` | Unknown: needs in-app UI capture |  | High |
| F266 | `touch_synthetic_flag` | Unknown: needs in-app UI capture |  | High |
| F267 | `battery_level_delta` | Measured |  | Medium |
| F268 | `battery_temp_variation` | Measured |  | Medium |
| F269 | `charging_state_changes` | Measured |  | Medium |
| F270 | `battery_static_over_session` | Unknown: needs install history |  | Medium |
| F271 | `accessibility_services_count` | Measured | Yes | Medium |
| F272 | `accessibility_can_gesture` | Measured | Yes | Medium |
| F273 | `accessibility_unknown_pkg` | Measured |  | Medium |
| F274 | `overlay_permission_apps` | Measured |  | Medium |
| F275 | `overlay_window_present` | Unknown: needs in-app UI capture |  | Medium |
| F276 | `screen_sharing_active` | Measured |  | Medium |
| F277 | `media_projection_active` | Unknown: not visible to apps |  | Medium |
| F278 | `developer_options_on` | Measured | Yes | Medium |
| F279 | `usb_debugging_on` | Measured | Yes | Medium |
| F280 | `adb_wifi_on` | Measured | Yes | Medium |
| F281 | `unknown_sources_enabled` | Measured |  | Medium |
| F282 | `vpn_active` | Measured | Yes | Medium |
| F283 | `device_admin_apps` | Measured |  | Medium |
| F284 | `notification_listener_apps` | Measured |  | Medium |
| F285 | `input_method_unknown` | Measured |  | Medium |
| F286 | `ip_asn` | Backend (planned) |  | High |
| F287 | `ip_asn_type` | Backend (planned) |  | High |
| F288 | `ip_country` | Backend (planned) |  | High |
| F289 | `ip_vs_sim_country` | Backend (planned) |  | High |
| F290 | `ip_vs_timezone` | Backend (planned) |  | High |
| F291 | `ip_vs_locale` | Backend (planned) |  | High |
| F292 | `vpn_proxy_flag` | Backend (planned) |  | High |
| F293 | `tor_exit_flag` | Backend (planned) |  | High |
| F294 | `datacenter_ip_flag` | Backend (planned) |  | High |
| F295 | `ip_reputation_score` | Backend (planned) |  | High |
| F296 | `tls_ja3_hash` | Backend (planned) |  | High |
| F297 | `tls_ja3_vs_cohort` | Backend (planned) |  | High |
| F298 | `http_header_order_hash` | Backend (planned) |  | High |
| F299 | `user_agent_vs_build` | Backend (computed) |  | High |
| F300 | `dns_resolver_class` | Backend (planned) |  | High |
| F301 | `network_type` | Backend (planned) |  | High |
| F302 | `rtt_ms` | Backend (planned) |  | High |
| F303 | `wifi_vs_cell_switches` | Backend (planned) |  | High |
| F304 | `ip_changes_in_session` | Backend (computed) |  | High |
| F305 | `request_timing_regularity` | Backend (computed) |  | High |
| F306 | `patch_level_regressed` | Backend (computed) | Yes | Per install |
| F307 | `verified_boot_regressed` | Backend (computed) | Yes | Per install |
| F308 | `bootloader_state_changed` | Backend (computed) | Yes | Per install |
| F309 | `fingerprint_changed` | Backend (computed) |  | Per install |
| F310 | `boot_count_reset_unexpected` | Backend (planned) |  | Per install |
| F311 | `uptime_vs_session_gap` | Backend (planned) |  | Per install |
| F312 | `os_version_downgrade` | Backend (computed) | Yes | Per install |
| F313 | `kernel_version_changed` | Backend (planned) |  | Per install |
| F314 | `sdk_version_changed` | Backend (computed) |  | Per install |
| F315 | `app_version_regression` | Backend (computed) | Yes | Per install |
| F316 | `attest_key_rotation_freq` | Backend (planned) |  | Per install |
| F317 | `attest_key_age_days` | Backend (planned) |  | Per install |
| F318 | `attest_chain_changed` | Backend (planned) |  | Per install |
| F319 | `key_reinstall_regen` | Backend (planned) |  | Per install |
| F320 | `distinct_attest_keys_per_install` | Backend (planned) |  | Per install |
| F321 | `key_created_in_session` | Backend (planned) |  | Per install |
| F322 | `devices_per_account_30d` | Backend (planned) |  | Per install |
| F323 | `accounts_per_device_30d` | Backend (planned) |  | Per install |
| F324 | `installs_per_key_24h` | Backend (planned) |  | Per install |
| F325 | `new_install_velocity` | Backend (planned) |  | Per install |
| F326 | `reinstall_count_30d` | Backend (planned) |  | Per install |
| F327 | `login_from_new_device_flag` | Backend (planned) |  | Per install |
| F328 | `payee_adds_in_session` | Backend (planned) |  | Per install |
| F329 | `time_since_install` | Backend (computed) |  | Per install |
| F330 | `max_level_last_30d` | Backend (computed) |  | Per install |
| F331 | `level4plus_count_30d` | Backend (computed) |  | Per install |
| F332 | `rule_hits_last_30d` | Backend (computed) |  | Per install |
| F333 | `anomaly_pct_trend` | Backend (planned) |  | Per install |
| F334 | `step_up_failures_30d` | Backend (planned) |  | Per install |
| F335 | `prior_fraud_flag` | Backend (planned) |  | Per install |
| F336 | `accounts_per_attest_cert_serial_24h` | Backend (planned) |  | Fleet |
| F337 | `devices_per_attest_intermediate` | Backend (computed) |  | Fleet |
| F338 | `devices_per_sensor_signature` | Backend (planned) |  | Fleet |
| F339 | `devices_per_ip24` | Backend (computed) |  | Fleet |
| F340 | `devices_per_asn_24h` | Backend (planned) |  | Fleet |
| F341 | `devices_per_payee` | Backend (planned) |  | Fleet |
| F342 | `shared_payee_count` | Backend (planned) |  | Fleet |
| F343 | `community_id_size` | Backend (planned) |  | Fleet |
| F344 | `community_emulator_share` | Backend (planned) |  | Fleet |
| F345 | `community_new_install_share` | Backend (planned) |  | Fleet |
| F346 | `community_shared_payee_share` | Backend (planned) |  | Fleet |
| F347 | `community_reputation_score` | Backend (planned) |  | Fleet |
| F348 | `entity_age_days` | Backend (planned) |  | Fleet |
| F349 | `graph_component_size` | Backend (planned) |  | Fleet |
| F350 | `farm_cluster_score` | Backend (planned) |  | Fleet |
| F351 | `probe_error_count` | Measured |  | Medium |
| F352 | `probe_timeout_count` | Unknown: planned (canary / self-hash) |  | Medium |
| F353 | `probe_blocked_count` | Measured |  | Medium |
| F354 | `probe_crash_count` | Unknown: planned (canary / self-hash) |  | Medium |
| F355 | `probe_path_disagreement_total` | Unknown: planned (canary / self-hash) |  | Medium |
| F356 | `probe_missing_count` | Measured |  | Medium |
| F357 | `canary_probe_failed` | Unknown: planned (canary / self-hash) |  | Medium |
| F358 | `canary_decoy_visible` | Unknown: planned (canary / self-hash) |  | Medium |
| F359 | `sdk_self_hash_match` | Unknown: planned (canary / self-hash) |  | Medium |
| F360 | `sdk_text_integrity` | Measured (native) | Yes | Medium |
| F361 | `sdk_version_expected` | Unknown: planned (canary / self-hash) |  | Medium |
| F362 | `probe_order_matches_nonce` | Unknown: planned (canary / self-hash) |  | Medium |
| F363 | `payload_counter_monotonic` | Backend |  | Medium |
| F364 | `payload_signature_valid` | Backend |  | Medium |
| F365 | `payload_age_ms` | Backend |  | Medium |
| F366 | `cert_pinning_failure` | Unknown: planned (canary / self-hash) |  | Medium |
| F367 | `jni_registered_natives_ok` | Unknown: planned (canary / self-hash) |  | Medium |
| F368 | `native_lib_load_path_ok` | Measured (native) | Yes | Medium |
| F369 | `probe_variance_too_low` | Unknown: planned (canary / self-hash) |  | Medium |
| F370 | `vector_matches_cohort_median_exactly` | Unknown: planned (canary / self-hash) |  | Medium |
