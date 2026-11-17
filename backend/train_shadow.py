"""Train the ML shadow models and write an evaluation report.

  python train_shadow.py

Training data = SYNTHETIC sessions (trustpoc/synth.py) plus, when DATABASE_URL is set, the feature
vectors of stored real sessions that the rules scored Level 1-2 (used as
low-risk negatives only). The report is a pipeline check, not an accuracy claim.
"""
import json
import time
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score
from sklearn.model_selection import train_test_split

from trustpoc.features import FEATURES
from trustpoc.ml import ShadowModels
from trustpoc.synth import FAMILIES, generate
from trustpoc.features import extract

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
FPR_BUDGET = 0.001  # 0.1% of genuine sessions, the design target


def load_real_low_risk():
    """Feature vectors of real sessions the rules scored Level 1-2, read from the database.

    These are pseudo-labelled negatives ("no indicators found"), not verified-clean devices, so a
    hidden attack that the rules miss would be learned as normal. Treat the result as a pipeline
    check until sessions have independently verified labels (attack lab, confirmed fraud).
    """
    import os
    from dotenv import load_dotenv
    load_dotenv(BASE / ".env")
    if not os.environ.get("DATABASE_URL"):
        print("DATABASE_URL not set: training on synthetic data only")
        return np.empty((0, len(FEATURES)))
    from trustpoc.store import PostgresStore, StoreError
    try:
        rows = PostgresStore(os.environ["DATABASE_URL"], os.environ.get("DB_SCHEMA", "public")) \
            .training_features(max_rules_level=2, limit=50000)
    except StoreError as exc:
        print(f"could not read sessions ({exc}): training on synthetic data only")
        return np.empty((0, len(FEATURES)))
    vectors = [[np.nan if r["features"].get(n) is None else r["features"][n] for n in FEATURES] for r in rows]
    print(f"read {len(vectors)} real low-risk sessions from the database")
    return np.array(vectors, dtype=float).reshape(-1, len(FEATURES))


def recall_at_fpr(scores_pos, scores_neg, fpr=FPR_BUDGET):
    thr = np.quantile(scores_neg, 1 - fpr) if len(scores_neg) else 0.5
    return float((scores_pos > thr).mean()) if len(scores_pos) else float("nan"), float(thr)


def main():
    t0 = time.time()
    sessions = generate()
    X = np.array([extract(p) for p, _, _ in sessions], dtype=float)
    Y = {f: np.array([lab[f] for _, lab, _ in sessions]) for f in FAMILIES}
    variant = np.array([v for _, _, v in sessions])

    real = load_real_low_risk()
    if len(real):
        X = np.vstack([X, real])
        for f in FAMILIES:
            Y[f] = np.concatenate([Y[f], np.zeros(len(real), dtype=int)])
        variant = np.concatenate([variant, np.array(["genuine_real"] * len(real))])

    idx_tr, idx_te = train_test_split(np.arange(len(X)), test_size=0.25, random_state=0, stratify=variant)
    genuine = np.isin(variant, ["genuine", "genuine_real"])

    meta = {"version": f"shadow-{time.strftime('%Y%m%d-%H%M')}",
            "data": "synthetic" + (f" + {len(real)} real low-risk sessions" if len(real) else "")}
    model = ShadowModels().fit(X[idx_tr], {f: Y[f][idx_tr] for f in FAMILIES}, genuine[idx_tr], meta)

    probs = model.head_probs(X[idx_te])
    g_te = genuine[idx_te]
    report = {"model": meta, "caveat": "Synthetic data: shows the pipeline works, not real-world accuracy.",
              "fpr_budget": FPR_BUDGET, "heads": {}, "unseen_variant": {}}

    for f in FAMILIES:
        pos = Y[f][idx_te] == 1
        rec, thr = recall_at_fpr(probs[f][pos], probs[f][g_te])
        hid = pos & np.char.endswith(variant[idx_te].astype(str), "hidden") & np.char.startswith(variant[idx_te].astype(str), f)
        rec_h, _ = recall_at_fpr(probs[f][hid], probs[f][g_te])
        report["heads"][f] = {
            "pr_auc": round(float(average_precision_score(Y[f][idx_te], probs[f])), 3),
            "recall_at_fpr": round(rec, 3), "recall_hidden_variant": round(rec_h, 3),
            "threshold": round(thr, 4), "positives_test": int(pos.sum()),
        }

    # Leave-one-variant-out: train without a family's hidden variant, test on it (design doc 6.1)
    for f in FAMILIES:
        held = f"{f}:hidden"
        keep = variant[idx_tr] != held
        m2 = ShadowModels().fit(X[idx_tr][keep], {k: Y[k][idx_tr][keep] for k in FAMILIES},
                                genuine[idx_tr][keep], meta)
        p2 = m2.head_probs(X[idx_te])[f]
        test_hidden = variant[idx_te] == held
        rec, _ = recall_at_fpr(p2[test_hidden], p2[g_te])
        report["unseen_variant"][held] = round(rec, 3)

    # Anomaly model admission (design doc 6.6): the autoencoder must beat Isolation Forest
    hidden_te = np.char.endswith(variant[idx_te].astype(str), "hidden")
    report["anomaly_models"] = {}
    for kind in ("iforest", "autoencoder"):
        pct = model.anomaly_pct(X[idx_te], kind)
        report["anomaly_models"][kind] = {
            "genuine_above_p99": round(float((pct[g_te] >= 99).mean()), 4),
            "attacks_above_p99": round(float((pct[~g_te] >= 99).mean()), 3),
            "hidden_above_p99": round(float((pct[hidden_te] >= 99).mean()), 3),
        }
    am = report["anomaly_models"]
    margin = 0.02  # must catch at least 2 points more attacks to replace the simpler model
    model.anomaly_kind = ("autoencoder" if am["autoencoder"]["attacks_above_p99"]
                          >= am["iforest"]["attacks_above_p99"] + margin else "iforest")
    report["anomaly_selected"] = model.anomaly_kind
    report["anomaly"] = {"share_genuine_above_p99": am[model.anomaly_kind]["genuine_above_p99"],
                         "share_attacks_above_p99": am[model.anomaly_kind]["attacks_above_p99"]}

    model.set_thresholds({f: h["threshold"] for f, h in report["heads"].items()})
    report["thresholds"] = model.thresholds
    model.save(DATA / "shadow_model.pkl")
    (DATA / "ml_report.json").write_text(json.dumps(report, indent=2))

    print(f"Trained {meta['version']} on {len(idx_tr)} sessions ({meta['data']}) in {time.time()-t0:.1f}s")
    print("SYNTHETIC DATA: pipeline check only, not an accuracy claim.\n")
    print(f"{'head':<20}{'PR-AUC':>8}{'recall@0.1%FPR':>16}{'hidden variant':>16}{'unseen variant':>16}")
    for f, h in report["heads"].items():
        print(f"{f:<20}{h['pr_auc']:>8}{h['recall_at_fpr']:>16}{h['recall_hidden_variant']:>16}"
              f"{report['unseen_variant'][f + ':hidden']:>16}")
    for kind, a in report["anomaly_models"].items():
        mark = "  <- selected" if kind == model.anomaly_kind else ""
        print(f"{kind:<12} >= p99: genuine {a['genuine_above_p99']:.2%}, attacks {a['attacks_above_p99']:.1%}, "
              f"hidden variants {a['hidden_above_p99']:.1%}{mark}")
    print(f"saved {DATA / 'shadow_model.pkl'} and ml_report.json; restart the server to load it")


if __name__ == "__main__":
    main()
