"""Stage 5: the ML model as a service, with an explicit contract.

The model (trustpoc/ml.py) is a set of 4 gradient-boosted threat heads plus an anomaly model.
It takes exactly the 25 numeric features in trustpoc/features.py FEATURES, in that order.

Contract
  input     the probes from normalize.normalize(); a probe that is absent becomes NaN
  coverage  share of the 25 features that are present. Below MIN_COVERAGE the model is not
            run ("insufficient_features") rather than guessing from a mostly empty vector.
  output    ml_level 1-5, per-head probabilities, anomaly percentile, top contributing
            features, and the exact feature vector that was scored (stored with the session)
  mode      ML_MODE=enforce  final level = max(rules, ML): the model can raise risk,
                             never lower what the rules found (default)
            ML_MODE=shadow   the model is scored and stored, the rules alone decide

The shipped model is trained on SYNTHETIC data (train_shadow.py). Its scores validate the
pipeline; they are not measured accuracy until it is retrained on collected sessions.
"""
import json
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path

from .features import FEATURES, extract

log = logging.getLogger(__name__)
MIN_COVERAGE = 0.6


@dataclass
class ModelOutcome:
    status: str                       # scored | insufficient_features | unavailable | error
    level: int | None = None
    features: dict = field(default_factory=dict)   # name -> value, None = missing
    coverage: float = 0.0
    missing: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)     # anomaly_pct, heads, top, explanation, agreement...
    version: str | None = None
    data: str | None = None


class ModelService:
    def __init__(self, data_dir: Path, mode: str = "enforce"):
        if mode not in ("enforce", "shadow"):
            raise ValueError("ML_MODE must be 'enforce' or 'shadow'")
        self.mode = mode
        self.models = None
        self.report = None
        try:
            from .ml import ShadowModels
            self.models = ShadowModels.load(data_dir / "shadow_model.pkl")
            trained_on = (self.models.meta.get("features") if self.models else None)
            if trained_on is not None and list(trained_on) != list(FEATURES):
                log.warning("model at %s was trained on a different feature list; not using it", data_dir)
                self.models = None
            rep = data_dir / "ml_report.json"
            self.report = json.loads(rep.read_text()) if rep.exists() else None
        except Exception as exc:  # noqa: BLE001  the service still runs, rules-only
            log.warning("ML model unavailable: %s", exc)
        if self.models is None:
            log.warning("no model at %s: run `python train_shadow.py`. Decisions will be rules-only.", data_dir)

    def info(self) -> dict:
        m = self.models
        return {
            "available": m is not None,
            "mode": self.mode,
            "version": m.meta.get("version") if m else None,
            "trained_on": m.meta.get("data") if m else None,
            "caveat": "Trained on synthetic data: scores validate the pipeline, not real-world accuracy.",
            "features": FEATURES,
            "min_coverage": MIN_COVERAGE,
            "anomaly_model": m.anomaly_kind if m else None,
            "head_thresholds": m.thresholds if m else None,
            "evaluation": self.report,
        }

    def score(self, probes: dict, rules_level: int) -> ModelOutcome:
        vector = extract({"probes": probes})
        feats = {n: (None if isinstance(v, float) and math.isnan(v) else v) for n, v in zip(FEATURES, vector)}
        missing = [n for n, v in feats.items() if v is None]
        coverage = round(1 - len(missing) / len(FEATURES), 3)
        out = ModelOutcome(status="unavailable", features=feats, coverage=coverage, missing=missing)
        if self.models is None:
            return out
        out.version, out.data = self.models.meta.get("version"), self.models.meta.get("data")
        if coverage < MIN_COVERAGE:
            out.status = "insufficient_features"
            return out
        try:
            result = self.models.score_features(vector)
        except Exception as exc:  # noqa: BLE001  a model failure must never break scoring
            log.exception("model scoring failed")
            out.status, out.detail = "error", {"error": type(exc).__name__}
            return out
        ml_risky = result["ml_level"] >= 4 or result["anomaly_pct"] >= 99.5
        result["agreement"] = ("agree" if ml_risky == (rules_level >= 4)
                               else "ml_only" if ml_risky else "rules_only")
        out.status, out.level, out.detail = "scored", result["ml_level"], result
        return out

    def final_level(self, rules_level: int, outcome: ModelOutcome) -> int:
        if self.mode == "enforce" and outcome.level is not None:
            return max(rules_level, outcome.level)
        return rules_level


# Each trust level owns a fixed band of the 0-100 risk score, so the score never contradicts
# the level: a Level 3 device always scores 40-59.
SCORE_BANDS = {1: (0, 19), 2: (20, 39), 3: (40, 59), 4: (60, 79), 5: (80, 100)}


def risk_score(level: int, outcome: ModelOutcome) -> tuple[int, dict]:
    """Risk score 0 (no risk) to 100 (critical).

    band      fixed by the final level (SCORE_BANDS)
    position  where in the band, from the model: the larger of the highest threat-head
              probability and the anomaly percentile above the median ((pct - 50) / 50).
              Without a scored model the score is the middle of the band.
    """
    low, high = SCORE_BANDS[level]
    if outcome.status == "scored":
        d = outcome.detail
        head = max(d["heads"].values()) if d.get("heads") else 0.0
        anomaly = max(0.0, (float(d.get("anomaly_pct", 0)) - 50) / 50)
        position, source = min(1.0, max(head, anomaly)), "model"
    else:
        position, source = 0.5, f"level only (model {outcome.status})"
    return round(low + position * (high - low)), {"band": [low, high], "position": round(position, 3), "from": source}
