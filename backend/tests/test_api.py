"""The HTTP surface: five endpoints, limits, auth, error messages."""
import json
import tempfile
import unittest
from pathlib import Path

from helpers import call, phone, small_model_dir
from trustpoc.api import Settings, create_app
from trustpoc.scoring import ModelService
from trustpoc.store import MemoryStore, StoreError


def make(**kw):
    store = kw.pop("store", MemoryStore())
    settings = Settings(store="memory", config_path=Path(tempfile.mkdtemp()) / "none.json", **kw)
    return create_app(settings, store, ModelService(small_model_dir(), settings.ml_mode)), store


class ApiTest(unittest.TestCase):
    def test_only_the_intended_routes_exist(self):
        app, _ = make()
        routes = {(m, r.path) for r in app.routes if hasattr(r, "methods") for m in r.methods if m not in ("HEAD", "OPTIONS")}
        self.assertEqual(routes - {("GET", "/docs"), ("GET", "/redoc"), ("GET", "/openapi.json"), ("GET", "/docs/oauth2-redirect")}, {
            ("GET", "/health"), ("GET", "/v1/challenge"), ("POST", "/v1/collect"), ("GET", "/v1/sessions/{pk}"),
            ("GET", "/v1/sessions"), ("GET", "/v1/model")})

    def test_health(self):
        app, _ = make()
        status, body = call(app, "GET", "/health")
        self.assertEqual((status, body["status"], body["database"], body["model"]), (200, "ok", "ok", "loaded"))

    def test_health_reports_a_down_database(self):
        class Down(MemoryStore):
            def ping(self):
                return False
        app, _ = make(store=Down())
        status, body = call(app, "GET", "/health")
        self.assertEqual(status, 503)
        self.assertEqual(body["detail"]["database"], "unreachable")

    def test_collect_returns_the_decision_and_stores_the_session(self):
        app, store = make()
        status, body = call(app, "POST", "/v1/collect", phone())
        self.assertEqual(status, 200)
        self.assertEqual(body["decision"]["level"], 3)
        self.assertEqual(body["decision"]["outcome"], "step_up")
        self.assertEqual(body["model"]["status"], "scored")
        self.assertFalse(body["duplicate"])
        self.assertEqual(len(store.list_sessions(None, None, 10)), 1)

    def test_client_ip_comes_from_the_connection_unless_a_proxy_is_trusted(self):
        app, store = make()
        call(app, "POST", "/v1/collect", phone(), headers={"x-forwarded-for": "198.51.100.7"})
        self.assertEqual(store.get(store.list_sessions(None, None, 1)[0]["id"])["session"]["client_ip"], "203.0.113.9")
        app, store = make(trust_proxy=True)
        call(app, "POST", "/v1/collect", phone(), headers={"x-forwarded-for": "6.6.6.6, 49.36.10.5, 10.24.134.135"})   # forged, client, Render hop
        self.assertEqual(store.get(store.list_sessions(None, None, 1)[0]["id"])["session"]["client_ip"], "49.36.10.5")

    def test_forwarded_client_skips_internal_hops(self):
        from trustpoc.api import forwarded_client
        self.assertEqual(forwarded_client("49.36.10.5"), "49.36.10.5")
        self.assertEqual(forwarded_client("1.2.3.4, 49.36.10.5, 10.0.0.2, 127.0.0.1"), "49.36.10.5")
        self.assertEqual(forwarded_client("6.6.6.6, 49.238.32.168, 162.158.107.64, 10.24.134.135"), "49.238.32.168")  # Render
        self.assertEqual(forwarded_client("2001:4860::1, 2606:4700::6810:1, 10.0.0.1"), "2001:4860::1")
        self.assertEqual(forwarded_client("10.0.0.7"), "10.0.0.7")            # all internal: the nearest hop
        self.assertIsNone(forwarded_client(""))
        self.assertIsNone(forwarded_client("garbage"))

    def test_retry_is_idempotent(self):
        app, store = make()
        _, first = call(app, "POST", "/v1/collect", phone(session_id="x"))
        status, again = call(app, "POST", "/v1/collect", phone(session_id="x"))
        self.assertEqual((status, again["duplicate"], again["id"]), (200, True, first["id"]))
        self.assertEqual(len(store.list_sessions(None, None, 10)), 1)

    def test_invalid_payload_gets_a_precise_422(self):
        app, store = make()
        bad = phone(action="withdraw")
        del bad["context_keys"]["install_id"]
        status, body = call(app, "POST", "/v1/collect", bad)
        self.assertEqual(status, 422)
        fields = {e["field"] for e in body["detail"]}
        self.assertTrue({"action", "context_keys.install_id"} <= fields)
        self.assertEqual(store.list_sessions(None, None, 10), [])   # nothing stored

    def test_not_json_is_422(self):
        app, _ = make()
        self.assertEqual(call(app, "POST", "/v1/collect", b"not json")[0], 422)

    def test_oversized_body_is_413(self):
        app, _ = make(max_body_kb=1)
        self.assertEqual(call(app, "POST", "/v1/collect", phone())[0], 413)

    def test_api_key_is_enforced_only_when_configured(self):
        app, _ = make(collect_api_key="secret-key")
        self.assertEqual(call(app, "POST", "/v1/collect", phone())[0], 401)
        self.assertEqual(call(app, "POST", "/v1/collect", phone(), headers={"x-api-key": "wrong"})[0], 401)
        self.assertEqual(call(app, "POST", "/v1/collect", phone(), headers={"x-api-key": "secret-key"})[0], 200)

    def test_storage_failure_is_503_and_safe_to_retry(self):
        class Broken(MemoryStore):
            def save(self, *a):
                raise StoreError("down")
        app, _ = make(store=Broken())
        status, body = call(app, "POST", "/v1/collect", phone())
        self.assertEqual(status, 503)
        self.assertIn("retry", body["detail"])

    def test_admin_endpoints_are_closed_without_a_token_setting(self):
        app, _ = make()
        for path in ("/v1/sessions", "/v1/model", "/v1/sessions/abc"):
            self.assertEqual(call(app, "GET", path)[0], 403, path)

    def test_admin_endpoints_with_the_token(self):
        app, _ = make(admin_token="adm")
        _, res = call(app, "POST", "/v1/collect", phone(install_id="i_admin00000000000000000000000001"))
        self.assertEqual(call(app, "GET", "/v1/sessions", headers={"x-admin-token": "nope"})[0], 401)
        h = {"x-admin-token": "adm"}

        status, listing = call(app, "GET", "/v1/sessions", headers=h)
        self.assertEqual((status, len(listing["sessions"])), (200, 1))
        self.assertEqual(listing["sessions"][0]["final_level"], 3)
        self.assertEqual(call(app, "GET", "/v1/sessions?min_level=4", headers=h)[1]["sessions"], [])
        self.assertEqual(len(call(app, "GET", "/v1/sessions?install_id=i_admin00000000000000000000000001", headers=h)[1]["sessions"]), 1)
        self.assertEqual(call(app, "GET", "/v1/sessions?min_level=9", headers=h)[0], 422)

        status, rec = call(app, "GET", f"/v1/sessions/{res['id']}", headers=h)
        self.assertEqual(status, 200)
        self.assertEqual(set(rec), {"session", "retrieved", "result"})
        self.assertEqual(rec["session"]["signals"]["F031"], ["Enforcing", 0])
        self.assertEqual(call(app, "GET", "/v1/sessions/not-a-uuid", headers=h)[0], 404)
        self.assertEqual(call(app, "GET", "/v1/sessions/00000000-0000-0000-0000-000000000000", headers=h)[0], 404)

        status, card = call(app, "GET", "/v1/model", headers=h)
        self.assertEqual(status, 200)
        self.assertEqual((card["available"], card["mode"], len(card["features"])), (True, "enforce", 25))

    def test_removed_endpoints_are_gone(self):
        app, _ = make(admin_token="adm")
        for method, path in [("POST", "/v1/nonce"), ("POST", "/v2/assess"), ("POST", "/v1/assess"), ("POST", "/v1/predict"),
                             ("POST", "/v1/features"), ("GET", "/v1/features"), ("POST", "/v1/bank/check"),
                             ("GET", "/v1/public-key"), ("GET", "/v1/decisions"), ("POST", "/v1/demo/frida"),
                             ("POST", "/v1/admin/reset"), ("GET", "/app"), ("GET", "/")]:
            self.assertEqual(call(app, method, path, b"{}", headers={"x-admin-token": "adm"})[0], 404, f"{method} {path}")


if __name__ == "__main__":
    unittest.main()
