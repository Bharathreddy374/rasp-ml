"""ML models (design doc 6.1, 6.2) and how they turn into a trust level.

- Anomaly model: Isolation Forest fit on low-risk sessions only; output is the
  anomaly percentile against those sessions.
- Threat heads: one gradient-boosted classifier per threat family
  (HistGradientBoosting: scikit-learn's LightGBM-style learner, native NaN support).

ML level (combined mode, "ML decides, rules guard"):
  2+ heads above their 0.1%-FPR threshold -> 5
  1 head above its threshold              -> 4
  anomaly >= p99.5                        -> 3
  anomaly >= p97                          -> 2
  otherwise                               -> 1
The final level is max(rules level, ML level): ML can raise risk, and hard
evidence from the rules (replay, bad signature, repackaging) can never be
overridden by a model.
"""
import math
import pickle
import time
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.neural_network import MLPRegressor
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .features import FEATURES, extract
from .synth import FAMILIES

HEAD_LABELS = {
    "hidden_root": "Hidden root", "instrumentation": "Instrumentation",
    "emulator_virtual": "Emulator / virtual", "app_tamper_clone": "App tamper / clone",
}
FEATURE_LABELS = {
    "root_su_paths_count": "su binary paths", "root_su_which": "su on PATH",
    "root_manager_count": "Root manager apps", "root_magisk_mounts": "Magisk mounts",
    "root_system_rw": "System mounted RW", "selinux_not_enforcing": "SELinux not enforcing",
    "props_test_keys": "Test-keys build", "emu_fingerprint": "Emulator fingerprint",
    "emu_hardware": "Emulator hardware", "emu_qemu_props": "QEMU properties",
    "sensor_count": "Sensor count", "rt_tracer_nonzero": "Tracer attached",
    "rt_debugger": "Debugger connected", "rt_frida_maps": "Frida in memory maps",
    "rt_frida_threads_count": "Frida threads", "rt_frida_port": "Frida port open",
    "rt_xposed": "Xposed present", "app_data_dir_bad": "Unexpected data directory",
    "ctx_developer_options": "Developer options", "ctx_adb_enabled": "USB debugging",
    "ctx_accessibility_count": "Accessibility services", "ctx_vpn": "VPN",
    "probe_error_count": "Failed probes", "probe_total_ms": "Scan duration (ms)",
    "libc_open_us": "libc open() latency (us)",
}


class ShadowModels:
    def __init__(self):
        self.anomaly = None
        self.anomaly_train_scores = None
        self.ae_prep = None  # imputer + scaler for the autoencoder
        self.ae = None
        self.ae_train_scores = None
        self.anomaly_kind = "iforest"  # which anomaly model decides; set by train_shadow.py
        self.heads: dict[str, HistGradientBoostingClassifier] = {}
        self.thresholds: dict[str, float] = {f: 0.5 for f in FAMILIES}
        self.baseline: np.ndarray | None = None
        self.meta: dict = {}

    # ---------- training ----------
    def fit(self, X: np.ndarray, Y: dict[str, np.ndarray], genuine_mask: np.ndarray, meta: dict):
        self.anomaly = make_pipeline(SimpleImputer(strategy="median"),
                                     IsolationForest(n_estimators=200, random_state=0))
        self.anomaly.fit(X[genuine_mask])
        self.anomaly_train_scores = np.sort(-self.anomaly.score_samples(X[genuine_mask]))
        # Autoencoder (design doc 6.2): 25 -> 12 -> 4 -> 12 -> 25 on low-risk devices only.
        # Admitted only if it beats Isolation Forest on held-out data (design doc 6.6).
        self.ae_prep = make_pipeline(SimpleImputer(strategy="median"), StandardScaler())
        Z = self.ae_prep.fit_transform(X[genuine_mask])
        self.ae = MLPRegressor(hidden_layer_sizes=(12, 4, 12), max_iter=400, random_state=0).fit(Z, Z)
        self.ae_train_scores = np.sort(self._ae_error(X[genuine_mask]))
        self.baseline = np.nanmedian(X[genuine_mask], axis=0)
        for fam in FAMILIES:
            clf = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.1,
                                                 class_weight="balanced", random_state=0)
            clf.fit(X, Y[fam])
            self.heads[fam] = clf
        self.meta = {**meta, "features": FEATURES, "trained_at": int(time.time())}
        return self

    def set_thresholds(self, thresholds: dict[str, float]):
        # never below 0.5: a head must also be more sure than not
        self.thresholds = {f: max(0.5, float(t)) for f, t in thresholds.items()}

    # ---------- scoring ----------
    def _ae_error(self, X: np.ndarray) -> np.ndarray:
        Z = self.ae_prep.transform(X)
        return ((self.ae.predict(Z) - Z) ** 2).mean(axis=1)

    def anomaly_pct(self, X: np.ndarray, kind: str | None = None) -> np.ndarray:
        if (kind or self.anomaly_kind) == "autoencoder":
            s, ref = self._ae_error(X), self.ae_train_scores
        else:
            s, ref = -self.anomaly.score_samples(X), self.anomaly_train_scores
        return np.searchsorted(ref, s) / len(ref) * 100

    def head_probs(self, X: np.ndarray) -> dict[str, np.ndarray]:
        return {f: m.predict_proba(X)[:, 1] for f, m in self.heads.items()}

    def level(self, probs: dict[str, float], anomaly_pct: float) -> int:
        hot = [f for f, p in probs.items() if p >= self.thresholds.get(f, 0.5)]
        if len(hot) >= 2:
            return 5
        if hot:
            return 4
        if anomaly_pct >= 99.5:
            return 3
        if anomaly_pct >= 97:
            return 2
        return 1

    def explain(self, x: np.ndarray, head: str, top: int = 5) -> list[dict]:
        """Occlusion: how much the head's probability drops when each feature is
        reset to the typical low-risk value. Positive = pushed risk up."""
        rows = np.repeat(x, len(FEATURES), axis=0)
        for i in range(len(FEATURES)):
            rows[i, i] = self.baseline[i]
        p0 = float(self.heads[head].predict_proba(x)[0, 1])
        ps = self.heads[head].predict_proba(rows)[:, 1]
        out = []
        for i, f in enumerate(FEATURES):
            delta = p0 - float(ps[i])
            v = x[0, i]
            if abs(delta) >= 0.01:
                out.append({"feature": f, "label": FEATURE_LABELS.get(f, f),
                            "value": None if math.isnan(v) else round(float(v), 3),
                            "impact": round(delta, 3)})
        out.sort(key=lambda d: -abs(d["impact"]))
        return out[:top]

    def score_features(self, x_list: list[float]) -> dict:
        x = np.array([x_list], dtype=float)
        pct = float(self.anomaly_pct(x)[0])
        probs = {f: round(float(p[0]), 3) for f, p in self.head_probs(x).items()}
        top = max(probs, key=probs.get)
        return {
            "anomaly_pct": round(pct, 1),
            "heads": probs,
            "top": top,
            "ml_level": self.level(probs, pct),
            "explanation": self.explain(x, top),
            "anomaly_model": self.anomaly_kind,
            "model": self.meta.get("version", "ml"),
            "data": self.meta.get("data", "unknown"),
        }

    def score_payload(self, payload: dict, rules_level: int) -> dict:
        out = self.score_features(extract(payload))
        ml_risky = out["ml_level"] >= 4 or out["anomaly_pct"] >= 99.5
        rules_risky = rules_level >= 4
        if ml_risky == rules_risky:
            out["agreement"] = "agree"
        elif ml_risky:
            out["agreement"] = "ml_only"  # ML sees something rules miss: analyst review
        else:
            out["agreement"] = "rules_only"  # e.g. crypto evidence the model cannot see
        return out

    # ---------- persistence ----------
    def save(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(pickle.dumps(self))
        tmp.replace(path)

    @staticmethod
    def load(path: Path) -> "ShadowModels | None":
        # Only load a file this service wrote itself; pickle must never come from outside.
        if not path.exists():
            return None
        return pickle.loads(path.read_bytes())
