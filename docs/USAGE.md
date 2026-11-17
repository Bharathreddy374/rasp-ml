# How to use

All commands are for **Windows PowerShell**. Run them from the repository root unless a step says otherwise.

## 1. Prerequisites

| Tool | Why | Notes |
|---|---|---|
| Android Studio (bundled JDK in `jbr`) | Build the app | Any recent version |
| Android SDK + **NDK 28.2.13676358** + **CMake 3.22.1** | Native probe library | Gradle downloads them on the first build if missing |
| Python 3.11+ | Backend | Tested on 3.14 |
| PostgreSQL (optional) | Store every assessment | e.g. a free Neon database |
| A phone on the same Wi-Fi as the laptop | Real-device test | Android 7.0+ (minSdk 24) |

## 2. Backend

```powershell
cd backend
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe train_shadow.py        # trains the ML shadow model into data/ (about 20 s)
```

Create `backend/.env` for your settings. **Never commit it**; it is already in `.gitignore`.

```
DATABASE_URL=postgresql://user:password@host/db?sslmode=require
ADMIN_TOKEN=choose-a-long-random-secret
```

Start the server:

```powershell
.\venv\Scripts\python.exe -m uvicorn app:app --host 0.0.0.0 --port 8000
```

- API docs: http://localhost:8000/docs
- Dashboard: http://localhost:8000/
- The first start downloads Google's attestation roots and revocation list. Set `TRUSTPOC_OFFLINE=1` to skip that, for tests.
- If Windows Firewall asks about Python, allow **Private networks**, or phones cannot reach the server.

Run the tests:

```powershell
$env:TRUSTPOC_OFFLINE = "1"; .\venv\Scripts\python.exe -m unittest discover -s tests
```

### Settings (environment variables)

| Variable | Default | Effect |
|---|---|---|
| `DATABASE_URL` | empty | Postgres. Each assessment goes into the `device_assessments` table. Without it, decisions still work and are not stored. |
| `ADMIN_TOKEN` | empty | Admin endpoints return 403 until set. Send it as the `X-Admin-Token` header. |
| `DEMO_MODE` | `0` | `1` trusts the simulator's attestation root (for the web demo only). **Never with real devices.** |
| `ALLOW_UNSIGNED_REPORTS` | `0` | `1` re-enables the legacy unsigned `POST /v1/features` endpoint. |
| `TRUST_PROXY` | `0` | `1` reads the client IP from `X-Forwarded-For` (behind Render or nginx). |
| `STRICT_HARDENING` | `0` | `1` requires trusted hardware attestation for login, add_payee and transfer. |

### `config.json`

```json
{
  "expected_package": ["com.example.demo"],
  "expected_cert_sha256": ["<sha256 of your signing certificate>"],
  "release_manifests": [ { "dex_digest": "...", "so_digest": "...", "arsc_crc": "...", "manifest_crc": "...", "assets_digest": "..." } ]
}
```

- **`expected_cert_sha256`** turns on repackaging detection (F008 / F081). The app reports its digest in `app.cert_sha256`, and the backend shows the attested one in `attestation.signing_digests`. Debug and release keys have different digests, so add both.
- **`release_manifests`** turns on APK code checks (F084–F092). For each release, generate an entry and paste it in:
  ```powershell
  .\venv\Scripts\python.exe tools\apk_manifest.py path\to\app-release.apk --version-code 1
  ```

## 3. Android app

Open `android/` in Android Studio and press **Run**. Or build from the command line:

```powershell
cd android
$env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"
.\gradlew.bat :app:installDebug
```

On the phone:

1. Connect the phone and laptop to the same Wi-Fi. Find the laptop IP with `ipconfig`.
2. Open the app. It scans automatically and lists all 370 signals with their status. Grey **NOT IMPLEMENTED** rows are sent as unknown.
3. Tap **Send to API**, enter `http://<laptop-ip>:8000` (the emulator uses `http://10.0.2.2:8000`), then tap **Assess device**.
4. The card shows the trust level, outcome, rules / ML levels, reasons, attestation verdict and payload size.

Launch the app from the home screen, **not with the debugger attached**. An attached debugger is real instrumentation and gives Level 4.

Expected on a genuine phone with developer options and USB debugging on: **Level 3, step-up**. With both off: Level 1–2.

## 4. What the app sends

1. `POST /v1/nonce {install_id, action}` returns a one-time nonce (60 s, bound to this install and action).
2. The app creates a TEE key with that nonce as its attestation challenge, rescans, and signs the payload.
3. `POST /v2/assess` (gzip) sends `{payload, signature, chain}`.

The signed payload:

```json
{
  "schema": 2, "install_id": "i_…", "action": "login", "nonce": "…", "counter": 7, "ts": 1794847441000, "scan_ms": 2082,
  "app":    { "package": "com.example.demo", "version_code": 1, "cert_sha256": ["87a3…"] },
  "device": { "manufacturer": "…", "model": "…", "release": "16", "sdk_int": 36, "security_patch": "…", "fingerprint": "…" },
  "signals": { "F031": ["Enforcing", 0], "F146": [0, 0], "F206": [1.014, 1], "F231": [0.029, 0] },
  "unknown": ["F034", "…"],
  "failed_groups": []
}
```

- Each signal is `[typed value, risk]`. The risk is the probe's own verdict: 0 SAFE, 1 INFO, 2 SUSPICIOUS, 3 ALERT.
- Not sent:
  - attestation rows (the certificate chain is sent instead);
  - server-side rows F286–F350 (the backend computes them);
  - names and descriptions;
  - raw sensor samples.
- Size is about 6 KB, 4–5 KB gzipped.

Before trusting any signal, the backend checks:
1. The nonce: unknown or reused means replay → Level 5.
2. The chain leads to Google's roots and is not revoked.
3. The signature matches the payload bytes → otherwise Level 5.
4. The counter has gone up.

See [FEATURES.md](FEATURES.md) for every signal.

## 5. Attack test: rooted emulator + Frida

This shows that detection works, not just that genuine phones pass.

1. **Create a rootable emulator.** Use a **Google APIs** system image, not "Google Play" (Play images do not allow `adb root`). Install it through Android Studio → SDK Manager, and create a device with it.
2. **Start the emulator** and install the app:
   ```powershell
   $adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
   & $adb -s emulator-5554 root
   & $adb -s emulator-5554 install -r android\app\build\outputs\apk\debug\app-debug.apk
   ```
3. **Baseline:** assess from the app (address `http://10.0.2.2:8000`). Expected: Level 5 with `EM_EMULATOR` (software attestation, untrusted root, zero-noise sensors, debuggable build).
4. **Add Frida.** Download `frida-server` and `frida-inject` for `android-x86_64` from https://github.com/frida/frida/releases and decompress the `.xz` files. Then push them with the test script:
   ```powershell
   & $adb -s emulator-5554 push frida-server /data/local/tmp/
   & $adb -s emulator-5554 push frida-inject /data/local/tmp/
   & $adb -s emulator-5554 push backend\tools\frida\hide_root.js /data/local/tmp/
   & $adb -s emulator-5554 shell "chmod 755 /data/local/tmp/frida-*; /data/local/tmp/frida-server -D"
   ```
5. **Inject the root-hiding hook** into the running app, then assess again:
   ```powershell
   $p = (& $adb -s emulator-5554 shell pidof com.example.demo).Trim()
   & $adb -s emulator-5554 shell "/data/local/tmp/frida-inject -p $p -s /data/local/tmp/hide_root.js -e"
   ```
   Expected: Level 5 with `RT_FRIDA` and `RT_CODE_PATCHED`. F146/F148–F150 show patched bytes on exactly the hooked functions, and F131 shows the Frida handshake.

If Windows application-control policy blocks Frida's Windows tools, this device-only method (`frida-inject`) still works.

## 6. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Connection error` in the app | Wrong IP, different Wi-Fi, or the firewall is blocking port 8000 |
| Level 5 `AP_PACKAGE_MISMATCH` | `expected_package` in `config.json` doesn't match the app's package |
| Level 5 `AT_NONCE_INVALID` | Request replayed, or more than 60 s between the nonce and the send |
| Level 4 `RT_TRACER_ATTACHED` | App started from Android Studio's debugger |
| Level 2 `AT_NO_ATTESTATION` | Device could not create an attested key (very old or broken keystore) |
| ML level `null`, "degraded" | `data/shadow_model.pkl` missing. Run `train_shadow.py`. |
| Many "Unknown" rows | Expected: native ART checks, touch capture, Play Integrity and per-model baselines are not built yet ([FEATURES.md](FEATURES.md)) |

## 7. Production gaps

- **ML:** trained on **synthetic data**. Collect real sessions first, retrain, and only then let ML raise levels.
- **History store:** in-memory. Move it to Redis or Postgres for restarts and multiple instances.
- **Play Integrity (F011–F015):** not integrated.
- **TLS:** release builds disallow cleartext. Put the backend behind HTTPS.
- **`/v1/decisions` and the dashboard:** not authenticated. Protect them before exposing the server.
- **Unknown signals:** 57 remain; see [FEATURES.md](FEATURES.md).
