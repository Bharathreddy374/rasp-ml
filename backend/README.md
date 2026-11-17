# Device Trust POC

A thin end-to-end slice of the Device Trust design: an Android SDK collects signals and
proves them with hardware key attestation; a Python backend verifies, scores and returns a
**signed 5-level trust decision**; a bank-side check verifies that decision before acting.
A live dashboard shows every decision with its reasons.

| Proves | Does not prove (yet) |
|---|---|
| Nonce-bound, signed, attested request–response (no replay, no forged payloads) | Hidden root (Magisk + DenyList / Shamiko): Kotlin probes are easy to hide from |
| Root, emulator, Frida, Xposed, debugger and clone detection on real signals | Play Integrity (needs Play Console + Play distribution) |
| Repackaged APK detection from the attested signing certificate | Deep learning (sensor 1D-CNN): needs real sensor data and privacy sign-off |
| Tiered rules → 5 levels → per-action allow / step-up / block | Scale, latency under load, SDK hardening (native code, obfuscation) |
| ML risk engine: 4 threat heads + anomaly model; final level = max(rules, ML), with per-decision explanations | Real ML accuracy: the models are trained on **synthetic** data |
| Developer phones get step-up, not a block | Device graph and farm detection |

## Feature-catalogue app protocol (schema 2, `/v2/assess`)

The Feature Catalogue Android app (`com.example.demo`) uses this flow:

1. `POST /v1/nonce {install_id, action}` returns a one-time nonce (60 s, bound to install + action).
2. The app creates an AndroidKeyStore EC key with that nonce as the attestation challenge.
3. It scans, then signs the compact JSON payload with that key:
   `{"schema":2, install_id, action, nonce, counter, ts, app, device, "signals": {"F016": [value, risk], ...}, "unknown": [...], "failed_groups": [...]}`
   where `risk` is the probe's own verdict (0 SAFE, 1 INFO, 2 SUSPICIOUS, 3 ALERT) and values are typed.
4. It sends `{payload: <signed JSON text>, signature, chain}` gzipped (`Content-Encoding: gzip`) to `POST /v2/assess`.

What travels and what does not:
- Sent: device-observed signals only. Names, categories and descriptions stay out (the backend has the catalogue).
- `unknown`: placeholder probes that do not measure anything yet. They are never treated as clean.
- Not sent: F001–F015 (the certificate chain is sent instead and verified here), and F286–F350 / F363–F365, which the backend computes (`trustpoc/server_signals.py`).

The backend maps signals to rule and ML probes in `trustpoc/signals.py`, without parsing any display text. Any other ALERT becomes the Tier C reason `DV_UNMAPPED_ALERTS`. Every assessment is stored in the Postgres table `device_assessments` when `DATABASE_URL` is set.

| Env var | Default | Meaning |
|---|---|---|
| `DEMO_MODE` | `0` | `1` trusts the simulator's attestation root (anyone with `data/sim/root_key.pem` can forge attestation). Demo servers only. |
| `ADMIN_TOKEN` | empty | Admin endpoints are closed (403) until it is set. Send it as the `X-Admin-Token` header. |
| `ALLOW_UNSIGNED_REPORTS` | `0` | `1` re-enables the old unsigned `POST /v1/features` for old app builds. |
| `TRUST_PROXY` | `0` | `1` reads the client IP from `X-Forwarded-For` (behind Render / nginx). |
| `STRICT_HARDENING` | `0` | `1` requires a trusted hardware attestation for login, payee and transfer actions. |

`config.json` → `expected_package` is `["com.example.demo"]`. To catch repackaged APKs, add your
release signing-certificate SHA-256 to `expected_cert_sha256`. The app sends it in `app.cert_sha256`.

## 0. Cloud demo (about 20 minutes)

The web app has three tabs: **Live decisions** (with buttons that run simulated devices end to end on the
server), **Try the model** (toggle device signals and watch rules + ML score them live) and **Model**
(evaluation and how a level is decided). No terminal is needed during the demo.

1. **GitHub:** create a private repository and upload the contents of this folder (`backend/`, `android/`, `README.md`).
2. **Render** (render.com, free tier): sign in with GitHub → **New → Web Service** → pick the repository →
   **Root Directory** `backend` → runtime **Docker** → instance **Free** → environment variable
   `ADMIN_TOKEN` = a secret of your choice (protects Clear) → **Create**. The build runs the tests and trains
   the model, about 5 minutes.
3. Open the URL Render gives you. Free instances sleep when idle: open it a few minutes before the meeting.
4. The Android app can use the same `https://…onrender.com` URL in its server field.

Any Docker host works the same way (Railway, Fly.io, a company VM). Locally:
`docker build -t trust-poc backend && docker run -p 8000:8000 trust-poc`.

**Demo mode** (`DEMO_MODE=1`, the default) trusts the simulator's test root so the scenario buttons work.
Set `DEMO_MODE=0` before testing anything real.

**5-minute demo script**
1. *Live decisions:* click Genuine → Developer → Frida → Emulator with Frida → Repackaged → Replay. For each, show
   the Rules / ML / Final split and the reasons.
2. *Try the model:* preset **Cloud phone (disguised emulator)**: rules say 3, the ML model says 4. This is the case
   ML exists for. Then **Renamed Frida**: the model is suspicious but under its threshold, which is honest:
   hidden variants need real attack-lab data.
3. *Model:* the evaluation table. Visible attacks are easy, hidden and never-seen variants are hard; the numbers
   come from synthetic data, so they show the pipeline, not real accuracy.

## Layout

```
backend/
  app.py              FastAPI app: API + dashboard
  dashboard.html      Live decisions view
  simulate.py         Device simulator: all demo scenarios without a phone
  train_shadow.py     Trains the ML shadow models and writes an evaluation report
  trustpoc/           Engine (framework-free): attestation, rules, nonces, signing,
                      features, synthetic data generator, shadow models
  tests/              15 unit tests (python -m unittest discover -s tests -v)
android/app/src/main/
  AndroidManifest.xml
  java/com/example/trustdemo/MainActivity.kt
  java/com/example/trustdemo/trust/TrustSdk.kt    nonce → probes → attest → sign → assess
  java/com/example/trustdemo/trust/Probes.kt      ~22 probes
```

## 1. Backend (15 minutes)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m unittest discover -s tests -v                  # expect 15 tests OK
python train_shadow.py                                   # ML shadow models, ~20 s
uvicorn app:app --host 0.0.0.0 --port 8000
```

Open http://localhost:8000 (dashboard) and http://localhost:8000/docs (API).
On start the server downloads Google's attestation roots and the revocation list; check the
log for `downloaded N Google attestation root(s)`. Without them a real phone tops out at Level 2.

**Rehearse without a phone:**

```bash
python simulate.py --trust-sim-root        # one time; then restart uvicorn
python simulate.py                         # runs all 7 scenarios, watch the dashboard
python simulate.py genuine frida replay    # or pick some
```

Delete `roots/sim_root.pem` before testing real devices for anything beyond the demo.

## 2. Android app (about 1 hour)

No Gradle files are shipped, to avoid version clashes with your Android Studio.

1. Android Studio → **New Project → Empty Views Activity**.
   Name **TrustDemo**, package **com.example.trustdemo**, language **Kotlin**, minimum SDK **API 28**.
2. Replace `app/src/main/AndroidManifest.xml` and `MainActivity.kt` with the files from this folder.
3. Create package `com.example.trustdemo.trust` and add `TrustSdk.kt` and `Probes.kt`.
4. Build. If the theme name differs, set `android:theme` in the manifest to the one in `res/values/themes.xml`.

Use **Run** (not Debug): an attached debugger is itself detected (`RT_TRACER_ATTACHED`).

### Emulator (the "attacker device")

Device Manager → create a Pixel with a **Google APIs** image (not "Google Play"), x86_64, API 34 or 35.
The server field defaults to `http://10.0.2.2:8000`, which reaches your laptop from the emulator.

### Your phone (the "genuine device")

1. Phone and laptop on the same Wi-Fi. Find the laptop IP (`ipconfig` / `ifconfig`), allow port 8000 in the firewall.
2. Install from Android Studio, then type `http://<laptop-ip>:8000` in the server field.
3. Tap **Transfer**. With USB debugging on, expect **Level 3 · developer class** (correct: step-up, not block).
4. On the dashboard click **Trust this build** to register your genuine signing certificate.
5. Turn **Developer options off** (the app stays installed), reopen the app, tap **Transfer** → **Level 1** if the
   bootloader is locked and the Google roots loaded.

Do not root your only phone for this POC. Root wipes data and may void the warranty; the emulator covers the attack cases.

## ML risk engine

`train_shadow.py` trains, on **synthetic** sessions (`trustpoc/synth.py`), the two model types from the design:

- **Anomaly models:** Isolation Forest and an autoencoder (25-12-4-12-25), both fit on low-risk sessions only. The
  autoencoder is used only if it catches at least 2 points more attacks on held-out data (the design's model
  admission rule); on the synthetic data it does (18.7% vs 6.8% of attacks, fewer genuine flagged), so it is in use.
- **Four threat heads:** gradient-boosted classifiers (scikit-learn's HistGradientBoosting, the same family as LightGBM)
  for hidden root, instrumentation, emulator/virtual, and app tamper/clone.

The models now **decide alongside the rules**: final level = max(rules level, ML level), so ML can raise risk but can
never lower hard evidence such as a replay or a bad signature. Each decision shows both levels and which signals
pushed the ML score up. ML scores stay on the server; the bank sees only the final signed level. Every request's feature vector is appended to
`data/sessions.jsonl`; rerun `train_shadow.py` and sessions the rules scored Level 1–2 join the training data as
low-risk examples. That is the real-data path the design describes.

The evaluation table is the most useful part to present, because it is honest:

| Head | Recall @ 0.1% FPR | Hidden variant | Unseen variant |
|---|---|---|---|
| Hidden root | 69% | 39% | 19% |
| Instrumentation | 80% | 61% | 21% |
| Emulator / virtual | 100% | 100% | 100% |
| App tamper / clone | 24% | 16% | 8% |

These come from synthetic data whose distributions are guesses, so they show the pipeline works, not real accuracy.
The pattern is the point: visible attacks are easy; hidden and never-seen variants are where the models struggle,
which is exactly why the design needs an attack lab, real data and shadow time before ML enforces anything.
Repackaging and replay show "rules only": those are cryptographic checks that the models cannot see.

Why there is no deep learning: the design uses it only for raw sensor and interaction sequences, which need real
device data and a privacy sign-off. It is planned for v1.1.

## 3. Demo scenarios

| # | Scenario | How | Expected | Main reason codes |
|---|---|---|---|---|
| 1 | Genuine phone | Phone, developer options off | **1 · Allow** | none |
| 2 | Developer phone | Phone, developer options + USB debugging on | **3 · Step-up** | `CX_DEVELOPER_OPTIONS`, `CX_ADB_ENABLED` |
| 3 | Emulator | App on the emulator | **4 · Block** (transfer) | `EM_EMULATOR`, `AT_UNTRUSTED_ROOT` |
| 4 | Emulator + Frida | Start frida-server on the emulator (below), tap Transfer | **5 · Block** | `EM_EMULATOR`, `RT_FRIDA` |
| 5 | Repackaged app | Build → Generate Signed APK with a **new** keystore; uninstall the debug app; install the new APK on the phone | **5 · Block** | `AP_SIGNATURE_MISMATCH` |
| 6 | Replay attack | `python simulate.py replay` | **5 · Block** | `AT_NONCE_INVALID` |
| 7 | Rooted phone | `python simulate.py rooted` (simulated; see the table at the top) | **5 · Block** | `DV_ROOT_MANAGER_APP`, `AT_BOOT_FAILED` |

**Frida on the emulator** (scenario 4):

```bash
pip install frida-tools
frida --version                       # note the version, e.g. 17.x.y
# download frida-server-<same version>-android-x86_64.xz from github.com/frida/frida/releases, unpack
adb root
adb push frida-server /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/frida-server
adb shell "/data/local/tmp/frida-server &"
frida -U -n TrustDemo                 # attach to the running app, then tap Transfer
```

Even without attaching, a running frida-server is caught by its listening port.

## 4. Suggested 10-minute demo flow

1. One slide: the three questions and the layered design.
2. Dashboard full-screen next to the phone mirror (scrcpy or Android Studio device mirroring).
3. Scenarios 1 → 2 → 3 → 4 → 5, then 6 and 7 from the simulator.
4. Open one decision: show attestation facts (boot state, lock, patch), reason codes and the ML shadow score.
5. Show the ML evaluation table and explain why ML is shadow-only.
6. Close with the "does not prove yet" table above and the v1.1 plan from the design doc.

Record a screen video of a full run the day before, as a fallback.

## 5. Troubleshooting

| Symptom | Fix |
|---|---|
| App says "Could not reach the server" | Same Wi-Fi? Correct IP? Firewall allows 8000? Server started with `--host 0.0.0.0`? |
| Real phone stays at Level 2 with `AT_UNTRUSTED_ROOT` | Google roots did not download (see server log). Check internet on the laptop and restart. |
| Real phone shows Level 4 `RT_TRACER_ATTACHED` | You launched with Debug. Stop and use Run, or open the app from the launcher. |
| Emulator key generation error | Use a Google APIs image, API 30+. Cold-boot the emulator. |
| Repackaged APK not detected | Click **Trust this build** for the genuine build first; the check needs an expected digest. |
| Phone and emulator both Level 3 | Developer options are on (expected). Turn them off on the phone for scenario 1. |

## 6. Production gaps (deliberate POC shortcuts)

- A fresh attested key per request; production keeps one per install, rotated every 30 days.
- Kotlin probes; production moves them to native code with raw syscalls and three-path checks.
- Cleartext HTTP; production uses TLS 1.3 with certificate pinning.
- Admin endpoints (`/v1/admin/*`) are unauthenticated; local demo only.
- In-memory state; production uses Redis for nonces and a feature store for history.
- The app shows the trust level for the demo; in production the app only learns allow / step-up / block.
- ML models trained on synthetic data; shadow only. No Play Integrity, no deep learning, no device graph.
- The shadow model is saved with pickle; load only files this service wrote itself.
