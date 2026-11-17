# How to use

All commands are for **Windows PowerShell**, run from the repository root unless a step says otherwise.

## 1. Prerequisites

| Tool | Why | Notes |
|---|---|---|
| Android Studio (bundled JDK in `jbr`) | Build the app | Any recent version |
| Android SDK + **NDK 28.2.13676358** + **CMake 3.22.1** | Native probe library | Gradle downloads them on the first build if missing |
| Python 3.11+ | Backend | Tested on 3.14 |
| PostgreSQL | Stores every session and result | e.g. a free Neon database |
| A phone on the same Wi-Fi as the laptop | Real-device test | Android 7.0+ (minSdk 24) |

## 2. Backend

```powershell
cd backend
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe train_shadow.py        # trains data/shadow_model.pkl (about 20 s)
```

Create `backend/.env` (git-ignored, never commit it):

```
DATABASE_URL=postgresql://user:password@host/db?sslmode=require
```

Start the server (tables are created at startup):

```powershell
$env:ADMIN_TOKEN = "choose-a-long-secret"          # enables the admin endpoints; optional
.\venv\Scripts\python.exe -m uvicorn app:app --host 0.0.0.0 --port 8000
```

- Health: http://localhost:8000/health · API docs: http://localhost:8000/docs
- If Windows Firewall asks about Python, allow **Private networks**, or phones cannot reach the server.
- All settings, the API, the pipeline, the database schema and the model contract are in [BACKEND.md](BACKEND.md).

Tests:

```powershell
.\venv\Scripts\python.exe -m unittest discover -s tests          # 70 tests, no database needed
```

### `config.json`

```json
{ "expected_cert_sha256": ["<sha256 of your signing certificate>"],
  "release_manifests": [ { "dex_digest": "...", "so_digest": "...", "arsc_crc": "...", "manifest_crc": "...", "assets_digest": "..." } ] }
```

- `expected_cert_sha256` turns on the signing-certificate check. Debug and release keys differ, so add both.
- `release_manifests` turns on the APK-code check. Generate an entry per release and paste it in:
  ```powershell
  .\venv\Scripts\python.exe tools\apk_manifest.py path\to\app-release.apk --version-code 1
  ```
- Both empty = both checks off.

## 3. Android app

Open `android/` in Android Studio and press **Run**, or build from the command line:

```powershell
cd android
$env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"
.\gradlew.bat :app:installDebug
```

On the phone:

1. Connect the phone and laptop to the same Wi-Fi. Find the laptop IP with `ipconfig`.
2. Open the app. It scans and lists all 370 signals with their status. Grey **NOT IMPLEMENTED** rows are sent as unknown.
3. Tap **Send to API**, enter the **full collector URL**, e.g. `http://192.168.1.5:8000/v1/collect` (the emulator reaches the laptop at `http://10.0.2.2:8000/v1/collect`), then tap **Send payload**. The URL is remembered.
4. The card shows the trust level and outcome, the **risk score (0–100) as a bar**, rules and ML levels, a one-line model summary, the signal counts (from the device, unknown, computed on the server), the reasons and the session id.
5. **Copy JSON** and **Share** produce the same payload ([PAYLOAD.md](PAYLOAD.md)).

Launch the app from the home screen, **not with the debugger attached**. A debugger is real instrumentation and gives Level 4.

Expected on a genuine phone: **Level 3, step-up** with developer options or USB / wireless debugging on, and Level 1–2 with them off.

## 4. See what was stored

With `ADMIN_TOKEN` set:

```powershell
$h = @{ "X-Admin-Token" = "choose-a-long-secret" }
Invoke-RestMethod http://localhost:8000/v1/sessions?limit=5 -Headers $h                 # latest sessions
Invoke-RestMethod "http://localhost:8000/v1/sessions?min_level=4" -Headers $h           # only risky ones
Invoke-RestMethod http://localhost:8000/v1/sessions/<id> -Headers $h                    # payload + retrievals + result
Invoke-RestMethod http://localhost:8000/v1/model -Headers $h                            # model card
```

Or query the tables directly: `collect_sessions`, `session_retrievals`, `session_results` ([BACKEND.md §8](BACKEND.md#8--persist-storepy-and-dbschemasql)).

## 5. Attack test: rooted emulator + Frida

This shows that detection works, not just that genuine phones pass.

1. **Create a rootable emulator** with a **Google APIs** system image, not "Google Play" (Play images do not allow `adb root`). Install it in Android Studio → SDK Manager.
2. **Start it**, get root and install the app:
   ```powershell
   $adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
   & $adb -s emulator-5554 root
   & $adb -s emulator-5554 install -r android\app\build\outputs\apk\debug\app-debug.apk
   ```
3. **Baseline:** send from the app (`http://10.0.2.2:8000/v1/collect`). Expected: Level 5 with `EM_EMULATOR` and `DV_DANGEROUS_PROPS` (debuggable build, zero-noise sensors).
4. **Add Frida.** Download `frida-server` and `frida-inject` for `android-x86_64` from https://github.com/frida/frida/releases, decompress the `.xz` files, and push them with the test script:
   ```powershell
   & $adb -s emulator-5554 push frida-server /data/local/tmp/
   & $adb -s emulator-5554 push frida-inject /data/local/tmp/
   & $adb -s emulator-5554 push backend\tools\frida\hide_root.js /data/local/tmp/
   & $adb -s emulator-5554 shell "chmod 755 /data/local/tmp/frida-*; /data/local/tmp/frida-server -D"
   ```
5. **Inject the root-hiding hook** into the running app, then send again:
   ```powershell
   $p = (& $adb -s emulator-5554 shell pidof com.example.demo).Trim()
   & $adb -s emulator-5554 shell "/data/local/tmp/frida-inject -p $p -s /data/local/tmp/hide_root.js -e"
   ```
   Expected: Level 5 with `RT_FRIDA` and `RT_CODE_PATCHED`. F146 / F148–F150 show patched bytes on exactly the hooked functions, and F131 shows the Frida handshake.

## 6. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Connection error` in the app | Wrong IP, different Wi-Fi, or the firewall is blocking port 8000 |
| Server won't start: `DATABASE_URL is not set` | Create `backend/.env`, or set `STORE=memory` for a throwaway run |
| `503 storage unavailable` | Database unreachable. Nothing was stored; the app can send again. |
| `422` with a field list | The payload does not match [PAYLOAD.md](PAYLOAD.md); the list names each field |
| Level 4 `RT_TRACER_ATTACHED` | App started from Android Studio's debugger |
| `ml_status: unavailable` | No model file. Run `train_shadow.py`. |
| `ml_status: insufficient_features` | Fewer than 60 % of the model's 25 features were present |
| Many "Unknown" rows | Expected: native ART checks, touch capture, Play Integrity and per-model baselines are not built yet ([FEATURES.md](FEATURES.md)) |

## 7. Production gaps

- **The payload is unsigned.** Use HTTPS and set `COLLECT_API_KEY` (the app does not send it yet).
- **The ML model is trained on synthetic data.** Collect real sessions, then retrain.
- **No rate limiting** (add it at the proxy).
- **57 signals are still unknown on the device**, and the server computes only the ones it has data for; see [FEATURES.md](FEATURES.md) and [BACKEND.md](BACKEND.md#5-limits-and-decisions).
