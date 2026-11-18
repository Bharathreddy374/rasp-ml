"""The request pipeline: one function per stage, one direction, one place to read the flow.

    POST /v1/collect
      1. validate     schema.CollectPayload                 (done by the API layer: 422 on failure)
      2. de-duplicate (install_id, session_id) seen before? -> return the stored result
      3. normalise    normalize.normalize()   signals -> named probes the rules and model use
     3b. integrity    integrity.evaluate()    key attestation chain + payload signature -> assurance
      4. retrieve     retrieval.retrieve()    request facts, history from the DB, config checks
      5. rules        rules.evaluate_probes() + retrieved evidence -> rules_level
      6. model        scoring.ModelService    25 features -> ML level, probabilities, explanation
      7. decide       final level, label, policy outcome per action
      8. persist      ONE transaction: session + retrievals + result
      9. respond      render() - the same shape for a fresh call, a retry and GET /v1/sessions/{id}
"""
import time
from pathlib import Path
from datetime import datetime, timezone

from . import integrity, normalize, retrieval, rules
from .attestation import TrustStore
from .schema import CollectPayload, parse_timestamp
from .scoring import ModelService, risk_score
from .store import Duplicate



class Pipeline:
    def __init__(self, store, model: ModelService, config: dict, geo=None,
                 trust: TrustStore | None = None, challenger: integrity.Challenger | None = None):
        self.store, self.model, self.config, self.geo = store, model, config, geo
        self.trust = trust or TrustStore(Path("/nonexistent"), online=False)
        self.challenger = challenger or integrity.Challenger()

    def run(self, payload: CollectPayload, req: retrieval.Request, raw_body: bytes = b"") -> dict:
        t0 = time.perf_counter()
        key = payload.context_keys

        # 2. de-duplicate: a client retry must not create a second row or a second decision
        existing = self.store.find(key.install_id, key.session_id)
        if existing:
            return render(existing, duplicate=True)

        now = datetime.now(timezone.utc)
        scan_time = parse_timestamp(payload.device.scan_timestamp)
        timings: dict[str, float] = {}

        def timed(name, fn):
            t = time.perf_counter()
            out = fn()
            timings[name] = round((time.perf_counter() - t) * 1000, 2)
            return out

        # 3. normalise
        norm = timed("normalize", lambda: normalize.normalize(payload))

        # 3b. integrity: attestation chain, challenge, body signature
        integ = timed("integrity", lambda: integrity.evaluate(
            payload, raw_body, req.signature, self.trust, self.challenger, self.config, now))

        # 4. retrieve
        retrieved = timed("retrieve", lambda: retrieval.retrieve(
            self.store, self.geo, payload, req, scan_time, self.config, now, integ))

        # 5. rules
        def run_rules():
            ev = rules.Evidence()
            rules.evaluate_probes(norm.probes, ev)
            for tier, code in retrieved.evidence:
                ev.add(tier, code)
            if norm.unmapped_alerts:
                ev.add("C", "DV_UNMAPPED_ALERTS")
            return ev, rules.decide_level(ev)
        ev, rules_level = timed("rules", run_rules)

        # 6. model
        outcome = timed("model", lambda: self.model.score(norm.probes, rules_level))

        # 7. decide
        retrieval.anomaly_trend(retrieved, outcome.detail.get("anomaly_pct"))   # F333 needs this session's score
        final = self.model.final_level(rules_level, outcome)
        score, score_basis = risk_score(final, outcome)
        reason_list = rules.reasons(ev)
        if final > rules_level:
            reason_list.append({"code": "ML_RISK", "tier": "ML", "text": rules.REASONS["ML_RISK"]})
        timings["total"] = round((time.perf_counter() - t0) * 1000, 2)

        session = {
            "install_id": key.install_id, "session_id": key.session_id, "scan_time": scan_time,
            "action": payload.action, "client_ip": req.client_ip, "net24": retrieval.net24(req.client_ip),
            "user_agent": (req.user_agent or "")[:300], "payload_bytes": req.payload_bytes,
            "app_version": payload.app.version_code, "device": payload.device.model_dump(),
            "app": payload.app.model_dump(), "signals": payload.signals, "unknown": payload.unknown,
            "failed_groups": payload.failed_groups, **retrieved.keys,
        }
        retrieval_row = {"server_signals": retrieved.server_signals, "not_computed": retrieved.not_computed, "history": retrieved.history,
                         "checks": retrieved.checks, "retrieval_ms": retrieved.retrieval_ms}
        result = {
            "rules_level": rules_level, "ml_level": outcome.level, "final_level": final, "risk_score": score,
            "label": rules.LABELS[final], "outcome": rules.policy_outcome(payload.action, final),
            "assurance": retrieved.keys["assurance"], "attestation": retrieved.keys["attestation"], "ml_mode": self.model.mode, "ml_status": outcome.status,
            "model_version": outcome.version, "model_data": outcome.data,
            "feature_coverage": outcome.coverage, "reasons": reason_list, "features": outcome.features,
            "ml": {**outcome.detail, "missing_features": outcome.missing, "score_basis": score_basis},
            "coverage": {
                "signals_received": norm.signals_received, "unknown_reported": norm.unknown_reported,
                "used_by_rules_and_model": len(norm.used), "undecidable": norm.undecidable,
                "unmapped_alerts": norm.unmapped_alerts, "probes_built": sorted(norm.probes),
            },
            "timings_ms": timings,
        }

        # 8. persist (one statement = one transaction)
        t_save = time.perf_counter()
        try:
            pk = self.store.save(session, retrieval_row, result)
        except Duplicate:  # two identical requests raced: the first one wins
            return render(self.store.find(key.install_id, key.session_id), duplicate=True)
        stored = {"session": {**session, "id": pk, "received_at": now}, "retrieved": retrieval_row, "result": result}
        response = render(stored, duplicate=False)
        # The stored timings end before the write; the response also reports the write and the true total.
        response["timings_ms"] = {**timings, "persist": round((time.perf_counter() - t_save) * 1000, 2),
                                  "total": round((time.perf_counter() - t0) * 1000, 2)}
        return response


def render(record: dict, duplicate: bool) -> dict:
    """API response for a stored or freshly stored session."""
    s, r, x = record["session"], record["retrieved"] or {}, record["result"] or {}
    ml = x.get("ml") or {}
    return {
        "id": s["id"], "install_id": s["install_id"], "session_id": s["session_id"],
        "received_at": s["received_at"] if isinstance(s["received_at"], str) else s["received_at"].isoformat(),
        "duplicate": duplicate,
        "decision": {
            "level": x.get("final_level"), "risk_score": x.get("risk_score"), "score_basis": ml.get("score_basis"),
            "label": x.get("label"), "outcome": x.get("outcome"),
            "action": s["action"], "assurance": x.get("assurance") or s.get("assurance"),
            "attestation": x.get("attestation") or s.get("attestation"),   # stored with the session
            "rules_level": x.get("rules_level"), "ml_level": x.get("ml_level"), "ml_mode": x.get("ml_mode"),
            "reasons": x.get("reasons"),
        },
        "model": {
            "status": x.get("ml_status"), "version": x.get("model_version"), "trained_on": x.get("model_data"),
            "feature_coverage": x.get("feature_coverage"), "missing_features": ml.get("missing_features"),
            "anomaly_pct": ml.get("anomaly_pct"), "heads": ml.get("heads"), "top_head": ml.get("top"),
            "agreement": ml.get("agreement"), "explanation": ml.get("explanation"), "features": x.get("features"),
        },
        "retrieved": {"server_signals": r.get("server_signals"), "not_computed": r.get("not_computed"), "history": r.get("history"), "checks": r.get("checks")},
        "coverage": x.get("coverage"),
        "timings_ms": x.get("timings_ms"),
    }
