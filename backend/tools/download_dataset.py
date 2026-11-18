"""Download every stored session as an ML dataset: one CSV row per session.

    python tools/download_dataset.py                       # all real sessions -> data/datasets/<time>/
    python tools/download_dataset.py --days 7              # only the last 7 days
    python tools/download_dataset.py --install i_819d...   # one phone
    python tools/download_dataset.py --include-test        # also load-test / deployment-check installs
    python tools/download_dataset.py --out my_dataset      # choose the output folder

Reads DATABASE_URL (and DB_SCHEMA) from backend/.env. Writes:

  dataset.csv       one row per session, columns in this order:
                      session   id, install, time, action, app version, device, network
                      ctx_*     the app's device_context block (SIM / network country, boot count, ...)
                      F001-F370 every catalogue signal: what the phone sent, or what the server
                                computed (F286-F365). Booleans are 1/0. Empty = missing (not measured,
                                reported unknown, or not computed); never read empty as "clean".
                      F###_risk the phone's own verdict for pair signals: 0 SAFE, 1 INFO, 2 SUSPICIOUS, 3 ALERT
                      mf_*      the 25 features the ML model saw (empty = missing)
                      assurance attested | failed | unverified (app 1.3+ sends key attestation)
                      att_*     the verified key attestation: security level, boot state, lock,
                                patch levels, chain / signature / nonce checks, install key id
                      results   rules / ML / final level, risk score, outcome, anomaly percentile,
                                per-head probabilities, reasons
  results.csv       one row per session: who / when / which device, assurance, and the ML and rule results
  dictionary.csv    one row per column: group and meaning (catalogue names from docs/FEATURES.md)
  summary.txt       row counts and level distribution

Labels: final_level comes from the rules plus a model trained on SYNTHETIC data. It is a
pseudo-label, not ground truth: verify sessions (attack lab, confirmed fraud) before training on it.
"""
import argparse
import csv
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(BACKEND / ".env")

from trustpoc.features import FEATURES  # noqa: E402
from trustpoc.store import PostgresStore, _fetch  # noqa: E402

CATALOGUE = [f"F{n:03d}" for n in range(1, 371)]
EXTRA_SIGNALS = ["battery_temp_c"]
TEST_INSTALLS = ("i_loadprobe%", "i_rendercheck%", "i_pg%")
CONTEXT_FIELDS = ["sim_country", "network_country", "timezone", "locale", "network_type", "boot_count",
                  "uptime_ms", "android_id_hash"]
HEADS = ["hidden_root", "instrumentation", "emulator_virtual", "app_tamper_clone"]

SESSION_COLUMNS = {
    "session_pk": "database id of the session",
    "install_id": "app install (one phone may have several installs)",
    "session_id": "the app's id for this scan",
    "received_at": "server time the payload arrived (UTC)",
    "scan_time": "phone clock when the scan ran (UTC)",
    "action": "action the scan was taken for (login, transfer, ...)",
    "app_version": "app versionCode",
    "manufacturer": "Build.MANUFACTURER", "model": "Build.MODEL", "android_release": "Android version",
    "sdk_int": "API level", "security_patch": "security patch date", "fingerprint": "Build.FINGERPRINT",
    "client_ip": "client IP as seen by the server", "net24": "/24 (IPv4) or /64 (IPv6) of the client IP",
    "asn": "autonomous system of the client IP (needs geo data)",
    "payload_bytes": "request size", "unknown_count": "signals the phone reported as unknown",
    "unknown_ids": "IDs the phone reported as unknown (; separated)",
    "failed_groups": "probe groups that crashed on the phone (; separated)",
}
# From collect_sessions.attestation (the verified chain summary); empty when no attestation was sent.
ATTEST_COLUMNS = {
    "assurance": "attested = Google-rooted key, valid signature, fresh nonce from this server; failed = attestation "
                 "sent but a check failed (see reason_codes AT_*); unverified = no attestation (app before 1.3)",
    "att_security_level": "where the install key lives: StrongBox | TEE | Software",
    "att_verified_boot_state": "Verified | SelfSigned | Unverified | Failed",
    "att_device_locked": "bootloader locked (1/0)",
    "att_os_version": "attested Android version, e.g. 160000 = 16",
    "att_os_patch_level": "attested OS patch level YYYYMM",
    "att_vendor_patch_level": "attested vendor patch level YYYYMMDD",
    "att_chain_valid": "certificate chain verifies link by link (1/0)",
    "att_root_trusted": "chain ends in a Google attestation root (1/0)",
    "att_revoked": "a certificate is on Google's revocation list (1/0)",
    "att_signature_valid": "request body signature valid with the attested key (1/0)",
    "att_nonce_fresh": "request nonce issued by this server within 5 minutes (1/0)",
    "att_nonce_reused": "request nonce was used before: replay (1 = replay)",
    "att_challenge_issued_here": "the key was created for a challenge this server issued (1/0)",
    "att_key_created_in_session": "the install key was created for this request (1/0)",
    "att_key_created_at": "when the install key was created (UTC)",
    "att_key_fp": "SHA-256 of the install key: the same value across sessions = the same key",
    "att_ca_fp": "SHA-256 of the certificate that issued the key",
}
ATTEST_FIELDS = [c[4:] for c in ATTEST_COLUMNS if c.startswith("att_")]

RESULT_COLUMNS = {
    "rules_level": "level 1-5 from the rules", "ml_level": "level 1-5 from the model (empty = not scored)",
    "final_level": "decided level 1-5 (max of rules and model in enforce mode)",
    "risk_score": "0-100 inside the band of final_level", "label": "SAFE ... CRITICAL",
    "outcome": "allow | step_up | block for this action", "ml_status": "scored | insufficient_features | unavailable",
    "ml_mode": "enforce | shadow", "model_version": "model that scored the session",
    "model_data": "what the model was trained on", "feature_coverage": "share of the 25 model features present",
    "anomaly_pct": "anomaly percentile vs genuine sessions (0-100)", "anomaly_model": "iforest | autoencoder",
    **{f"head_{h}": f"model probability of {h.replace('_', ' ')}" for h in HEADS},
    "top_head": "most likely threat class", "agreement": "rules vs model: agree | ml_higher | ml_lower",
    "reason_codes": "rule reasons (; separated)", "reason_tiers": "tier of each reason (; separated)",
    "server_signals_computed": "backend signals computed for this session",
    "server_signals_not_computed": "backend signals not computed (reason stored in the database)",
}

QUERY = """
SELECT s.id, s.install_id, s.session_id, s.received_at, s.scan_time, s.action, s.app_version,
       s.device, s.client_ip, s.net24, s.asn, s.payload_bytes, s.signals, s.unknown, s.failed_groups,
       s.device_context, r.server_signals, r.not_computed, s.attestation, x.assurance,
       x.rules_level, x.ml_level, x.final_level, x.risk_score, x.label, x.outcome, x.ml_status, x.ml_mode,
       x.model_version, x.model_data, x.feature_coverage, x.reasons, x.features, x.ml
  FROM collect_sessions s
  JOIN session_results x ON x.session_id = s.id
  LEFT JOIN session_retrievals r ON r.session_id = s.id
 WHERE {where}
 ORDER BY s.received_at
"""


def cell(v):
    """CSV value: booleans 1/0, missing empty, nested values as JSON."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, (dict, list)):
        return json.dumps(v, separators=(",", ":"))
    if isinstance(v, datetime):
        return v.astimezone(timezone.utc).isoformat()
    return v


def as_json(v):
    return json.loads(v) if isinstance(v, str) else (v or {})


def catalogue_names() -> dict:
    """F016 -> 'ro_debuggable (Measured, variance High)' from docs/FEATURES.md, when the repo has it."""
    doc = BACKEND.parent / "docs" / "FEATURES.md"
    names = {}
    if doc.exists():
        for m in re.finditer(r"^\| (F\d{3}) \| `([^`]+)` \| ([^|]+)\|[^|]*\| ([^|]+)\|", doc.read_text(encoding="utf-8"), re.M):
            names[m.group(1)] = f"{m.group(2)} ({m.group(3).strip()}, variance {m.group(4).strip()})"
    return names


def main() -> int:
    ap = argparse.ArgumentParser(description="Download stored sessions as an ML dataset (CSV).")
    ap.add_argument("--out", help="output folder (default: data/datasets/<UTC time>)")
    ap.add_argument("--days", type=int, help="only sessions received in the last N days")
    ap.add_argument("--install", help="only this install_id")
    ap.add_argument("--include-test", action="store_true", help="keep load-test and deployment-check installs")
    args = ap.parse_args()

    if not os.environ.get("DATABASE_URL"):
        print("DATABASE_URL is not set (backend/.env)", file=sys.stderr)
        return 1

    where, params = ["TRUE"], []
    if args.days:
        where.append("s.received_at >= %s")
        params.append(datetime.now(timezone.utc) - timedelta(days=args.days))
    if args.install:
        where.append("s.install_id = %s")
        params.append(args.install)
    if not args.include_test:
        where += ["s.install_id NOT LIKE %s"] * len(TEST_INSTALLS)
        params += TEST_INSTALLS

    store = PostgresStore(os.environ["DATABASE_URL"], os.environ.get("DB_SCHEMA", "public"))
    rows = store._run(lambda cur: _fetch(cur, QUERY.format(where=" AND ".join(where)), tuple(params)))
    if not rows:
        print("no sessions match")
        return 0

    # Pair signals get a _risk column, but only IDs that were ever sent as a pair.
    pair_ids = sorted({k for r in rows for k, v in as_json(r["signals"]).items() if isinstance(v, list)})
    signal_cols = []
    for fid in CATALOGUE + EXTRA_SIGNALS:
        signal_cols.append(fid)
        if fid in pair_ids:
            signal_cols.append(f"{fid}_risk")
    header = (list(SESSION_COLUMNS) + [f"ctx_{c}" for c in CONTEXT_FIELDS] + signal_cols
              + [f"mf_{f}" for f in FEATURES] + list(ATTEST_COLUMNS) + list(RESULT_COLUMNS))

    out = Path(args.out) if args.out else BACKEND / "data" / "datasets" / datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)

    result_header = ["session_pk", "install_id", "session_id", "received_at", "action", "app_version",
                     "manufacturer", "model", "android_release", "assurance", "att_key_fp"] + list(RESULT_COLUMNS)
    levels, installs = Counter(), set()
    with open(out / "dataset.csv", "w", newline="", encoding="utf-8") as f,             open(out / "results.csv", "w", newline="", encoding="utf-8") as fr:
        w, wr = csv.writer(f), csv.writer(fr)
        w.writerow(header)
        wr.writerow(result_header)
        for r in rows:
            dev, sig, srv = as_json(r["device"]), as_json(r["signals"]), as_json(r["server_signals"])
            ctx, feats, ml = as_json(r["device_context"]), as_json(r["features"]), as_json(r["ml"])
            unknown, reasons, heads = as_json(r["unknown"]) or [], as_json(r["reasons"]) or [], ml.get("heads") or {}
            row = {
                "session_pk": r["id"], "install_id": r["install_id"], "session_id": r["session_id"],
                "received_at": r["received_at"], "scan_time": r["scan_time"], "action": r["action"],
                "app_version": r["app_version"], **{k: dev.get(k) for k in
                ("manufacturer", "model", "android_release", "sdk_int", "security_patch", "fingerprint")},
                "client_ip": r["client_ip"], "net24": r["net24"], "asn": r["asn"], "payload_bytes": r["payload_bytes"],
                "unknown_count": len(unknown), "unknown_ids": ";".join(unknown),
                "failed_groups": ";".join(as_json(r["failed_groups"]) or []),
                **{f"ctx_{c}": ctx.get(c) for c in CONTEXT_FIELDS},
            }
            for fid in CATALOGUE + EXTRA_SIGNALS:
                v = sig.get(fid, srv.get(fid))   # phone first; F286-F365 come from the server
                if isinstance(v, list):
                    row[fid], row[f"{fid}_risk"] = v[0], v[1]
                else:
                    row[fid] = v
            row.update({f"mf_{f}": feats.get(f) for f in FEATURES})
            att = as_json(r["attestation"])
            row["assurance"] = r["assurance"]
            row.update({f"att_{k}": att.get(k) for k in ATTEST_FIELDS})
            row["att_key_created_at"] = att.get("created_at")
            if att and "nonce_reused" not in att:
                row["att_nonce_reused"] = False
            row.update({
                **{k: r[k] for k in ("rules_level", "ml_level", "final_level", "risk_score", "label", "outcome",
                                     "ml_status", "ml_mode", "model_version", "model_data", "feature_coverage")},
                "anomaly_pct": ml.get("anomaly_pct"), "anomaly_model": ml.get("anomaly_model"),
                **{f"head_{h}": (heads.get(h) if not isinstance(heads.get(h), dict) else heads[h].get("p")) for h in HEADS},
                "top_head": ml.get("top"), "agreement": ml.get("agreement"),
                "reason_codes": ";".join(x["code"] for x in reasons),
                "reason_tiers": ";".join(str(x.get("tier", "")) for x in reasons),
                "server_signals_computed": len(srv), "server_signals_not_computed": len(as_json(r["not_computed"])),
            })
            w.writerow([cell(row.get(c)) for c in header])
            wr.writerow([cell(row.get(c)) for c in result_header])
            levels[r["final_level"]] += 1
            installs.add(r["install_id"])

    names = catalogue_names()
    with open(out / "dictionary.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["column", "group", "meaning"])
        for c in header:
            if c in SESSION_COLUMNS:
                w.writerow([c, "session", SESSION_COLUMNS[c]])
            elif c.startswith("ctx_"):
                w.writerow([c, "device_context", f"app device_context.{c[4:]}"])
            elif c.endswith("_risk"):
                w.writerow([c, "signal_risk", f"phone's verdict for {c[:-5]}: 0 SAFE, 1 INFO, 2 SUSPICIOUS, 3 ALERT"])
            elif c in CATALOGUE or c in EXTRA_SIGNALS:
                w.writerow([c, "server_signal" if 286 <= int(c[1:] if c[1:].isdigit() else 0) <= 365 else "signal",
                            names.get(c, c)])
            elif c.startswith("mf_"):
                w.writerow([c, "model_feature", f"ML input {c[3:]} (empty = missing)"])
            elif c in ATTEST_COLUMNS:
                w.writerow([c, "attestation", ATTEST_COLUMNS[c]])
            else:
                w.writerow([c, "result", RESULT_COLUMNS[c]])

    assured = Counter(r["assurance"] for r in rows)
    summary = [f"sessions: {len(rows)}", f"installs: {len(installs)}", f"columns: {len(header)}",
               "final_level: " + ", ".join(f"L{k}={v}" for k, v in sorted(levels.items())),
               "assurance: " + ", ".join(f"{k}={v}" for k, v in sorted(assured.items())),
               f"first: {cell(rows[0]['received_at'])}", f"last: {cell(rows[-1]['received_at'])}",
               "test installs: " + ("included" if args.include_test else "excluded")]
    (out / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    print("\n".join("  " + s for s in summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
