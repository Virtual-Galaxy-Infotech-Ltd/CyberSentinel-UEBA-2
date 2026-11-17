"""Tests for the Dashboard Layout API (SN 23, Story 3.1).

Coverage:
  - AuthStore.get/set/delete_dashboard_prefs (unit)
  - GET /api/dashboard/layout
  - PUT /api/dashboard/layout  (valid + invalid inputs)
  - DELETE /api/dashboard/layout
  - Unauthenticated access to PUT / DELETE returns 401
  - Each analyst's layout is isolated (multi-user)
  - Reset reverts to default (null layout)
"""

import json
import sys
import os
import tempfile
import unittest

# Make sure the venv packages are importable when run directly.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "venv", "lib",
                                "python3.12", "site-packages"))

import ueba_auth
import ueba_dashboard_server as server


# ── Minimal valid layout payloads ────────────────────────────────────────────

TAB_PANELS = [
    "tab-overview", "tab-incidents", "tab-feed", "tab-users", "tab-campaigns",
    "tab-endpoints", "tab-false-positives", "tab-alerting", "tab-reports",
    "tab-watchlist", "tab-threatmap",
]

OVERVIEW_ROWS = [
    "ov-banner", "ov-row-gauge", "ov-row-recent", "ov-row-dist",
    "ov-ai-analyst", "ov-row-sigs", "ov-row-mitre",
]

OVERVIEW_PANELS = [
    "ov-gauge", "ov-radar", "ov-timeline",
    "ov-recent-alerts", "ov-top-users", "ov-endpoints-widget",
    "ov-score-dist", "ov-heatmap",
    "ov-top-sigs", "ov-rec-actions", "ov-mitre", "ov-health",
]

SAMPLE_LAYOUT = {
    "panels":          [{"id": p, "visible": True}  for p in TAB_PANELS],
    "overview_rows":   [{"id": r, "visible": True}  for r in OVERVIEW_ROWS],
    "overview_panels": [{"id": p, "visible": True}  for p in OVERVIEW_PANELS],
    "other":           [{"id": "fp-patterns", "visible": True},
                        {"id": "fp-list",     "visible": False}],
}


# ── AuthStore unit tests ──────────────────────────────────────────────────────

class TestAuthStoreDashboardPrefs(unittest.TestCase):

    def setUp(self):
        self.db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db.close()
        self.store = ueba_auth.AuthStore(self.db.name)

    def tearDown(self):
        self.store._conn.close()
        os.unlink(self.db.name)

    def test_get_returns_none_when_no_prefs(self):
        self.assertIsNone(self.store.get_dashboard_prefs("local:nobody"))

    def test_set_then_get_roundtrip(self):
        self.store.set_dashboard_prefs("local:alice", SAMPLE_LAYOUT)
        result = self.store.get_dashboard_prefs("local:alice")
        self.assertEqual(result["panels"][0]["id"], "tab-overview")
        self.assertEqual(result["other"][1]["visible"], False)

    def test_set_overwrites_previous_value(self):
        self.store.set_dashboard_prefs("local:alice", SAMPLE_LAYOUT)
        updated = dict(SAMPLE_LAYOUT)
        updated["panels"] = [{"id": "tab-incidents", "visible": True}]
        self.store.set_dashboard_prefs("local:alice", updated)
        result = self.store.get_dashboard_prefs("local:alice")
        self.assertEqual(len(result["panels"]), 1)
        self.assertEqual(result["panels"][0]["id"], "tab-incidents")

    def test_delete_returns_true_when_row_existed(self):
        self.store.set_dashboard_prefs("local:alice", SAMPLE_LAYOUT)
        self.assertTrue(self.store.delete_dashboard_prefs("local:alice"))

    def test_delete_returns_false_when_no_row(self):
        self.assertFalse(self.store.delete_dashboard_prefs("local:nobody"))

    def test_delete_removes_the_row(self):
        self.store.set_dashboard_prefs("local:alice", SAMPLE_LAYOUT)
        self.store.delete_dashboard_prefs("local:alice")
        self.assertIsNone(self.store.get_dashboard_prefs("local:alice"))

    def test_prefs_are_per_user(self):
        layout_b = dict(SAMPLE_LAYOUT)
        layout_b["panels"] = [{"id": "tab-incidents", "visible": True}]
        self.store.set_dashboard_prefs("local:alice", SAMPLE_LAYOUT)
        self.store.set_dashboard_prefs("local:bob",   layout_b)
        alice = self.store.get_dashboard_prefs("local:alice")
        bob   = self.store.get_dashboard_prefs("local:bob")
        self.assertEqual(alice["panels"][0]["id"], "tab-overview")
        self.assertEqual(bob["panels"][0]["id"],   "tab-incidents")

    def test_handles_corrupt_json_gracefully(self):
        self.store._conn.execute(
            "INSERT OR REPLACE INTO dashboard_prefs (sub, layout_json, updated_at) "
            "VALUES (?, ?, ?)",
            ("local:corrupt", "not-json", "2024-01-01T00:00:00+00:00"),
        )
        self.store._conn.commit()
        self.assertIsNone(self.store.get_dashboard_prefs("local:corrupt"))


# ── Flask API tests ───────────────────────────────────────────────────────────

class TestDashboardLayoutAPI(unittest.TestCase):

    def setUp(self):
        self.db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db.close()
        self._store = ueba_auth.AuthStore(self.db.name)

        server.app.config["TESTING"] = True
        self.client = server.app.test_client()

        # Patch the module-level helpers used by the view functions.
        self._orig_auth_avail = server.AUTH_MODULE_AVAILABLE
        server.AUTH_MODULE_AVAILABLE = True
        ueba_auth._STATE["store"] = self._store

    def tearDown(self):
        server.AUTH_MODULE_AVAILABLE = self._orig_auth_avail
        ueba_auth._STATE["store"] = None
        self._store._conn.close()
        os.unlink(self.db.name)

    # ── helpers ──────────────────────────────────────────────────────────────

    def _as_user(self, sub: str):
        """Context manager that makes current_user() return a stub for `sub`."""
        import unittest.mock as mock
        return mock.patch.object(ueba_auth, "current_user",
                                 return_value={"sub": sub, "role": "analyst"})

    def _get(self, sub=None):
        ctx = self._as_user(sub) if sub else _nullctx()
        with ctx:
            return self.client.get("/api/dashboard/layout")

    def _put(self, payload, sub=None):
        ctx = self._as_user(sub) if sub else _nullctx()
        with ctx:
            return self.client.put(
                "/api/dashboard/layout",
                data=json.dumps(payload),
                content_type="application/json",
            )

    def _delete(self, sub=None):
        ctx = self._as_user(sub) if sub else _nullctx()
        with ctx:
            return self.client.delete("/api/dashboard/layout")

    # ── GET ───────────────────────────────────────────────────────────────────

    def test_get_unauthenticated_returns_null_layout(self):
        import unittest.mock as mock
        with mock.patch.object(ueba_auth, "current_user", return_value=None):
            r = self.client.get("/api/dashboard/layout")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertTrue(body["ok"])
        self.assertIsNone(body["layout"])
        self.assertFalse(body["is_custom"])

    def test_get_returns_null_when_no_prefs_saved(self):
        r = self._get(sub="local:alice")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertIsNone(body["layout"])
        self.assertFalse(body["is_custom"])

    def test_get_returns_saved_layout(self):
        self._store.set_dashboard_prefs("local:alice", SAMPLE_LAYOUT)
        r = self._get(sub="local:alice")
        body = r.get_json()
        self.assertTrue(body["ok"])
        self.assertTrue(body["is_custom"])
        self.assertEqual(body["layout"]["panels"][0]["id"], "tab-overview")

    # ── PUT ───────────────────────────────────────────────────────────────────

    def test_put_unauthenticated_returns_401(self):
        import unittest.mock as mock
        with mock.patch.object(ueba_auth, "current_user", return_value=None):
            r = self.client.put(
                "/api/dashboard/layout",
                data=json.dumps(SAMPLE_LAYOUT),
                content_type="application/json",
            )
        self.assertEqual(r.status_code, 401)

    def test_put_valid_layout_saves_and_returns_ok(self):
        r = self._put(SAMPLE_LAYOUT, sub="local:alice")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])
        saved = self._store.get_dashboard_prefs("local:alice")
        self.assertIsNotNone(saved)

    def test_put_persists_visibility_false(self):
        payload = {
            "panels": [{"id": "tab-overview", "visible": True},
                       {"id": "tab-incidents", "visible": False}],
        }
        self._put(payload, sub="local:alice")
        saved = self._store.get_dashboard_prefs("local:alice")
        incidents = next(p for p in saved["panels"] if p["id"] == "tab-incidents")
        self.assertFalse(incidents["visible"])

    def test_put_unknown_panel_id_returns_400(self):
        payload = {"panels": [{"id": "not-a-real-panel", "visible": True}]}
        r = self._put(payload, sub="local:alice")
        self.assertEqual(r.status_code, 400)
        self.assertIn("unknown panel id", r.get_json()["error"])

    def test_put_duplicate_panel_id_returns_400(self):
        payload = {"panels": [{"id": "tab-overview", "visible": True},
                               {"id": "tab-overview", "visible": False}]}
        r = self._put(payload, sub="local:alice")
        self.assertEqual(r.status_code, 400)
        self.assertIn("duplicate", r.get_json()["error"])

    def test_put_non_boolean_visible_returns_400(self):
        payload = {"panels": [{"id": "tab-overview", "visible": "yes"}]}
        r = self._put(payload, sub="local:alice")
        self.assertEqual(r.status_code, 400)

    def test_put_non_list_field_returns_400(self):
        payload = {"panels": "not-a-list"}
        r = self._put(payload, sub="local:alice")
        self.assertEqual(r.status_code, 400)

    def test_put_overview_rows_validates_row_ids(self):
        payload = {
            "overview_rows": [{"id": "ov-row-gauge", "visible": True},
                               {"id": "ov-row-recent", "visible": False}],
        }
        r = self._put(payload, sub="local:alice")
        self.assertEqual(r.status_code, 200)

    def test_put_overview_panels_accepts_valid_sub_panel_ids(self):
        payload = {
            "overview_panels": [{"id": "ov-gauge", "visible": True},
                                 {"id": "ov-timeline", "visible": False}],
        }
        r = self._put(payload, sub="local:alice")
        self.assertEqual(r.status_code, 200)

    def test_put_other_panels_accepts_fp_ids(self):
        payload = {
            "other": [{"id": "fp-patterns", "visible": True},
                      {"id": "fp-list", "visible": False}],
        }
        r = self._put(payload, sub="local:alice")
        self.assertEqual(r.status_code, 200)

    def test_put_full_layout_all_four_fields(self):
        r = self._put(SAMPLE_LAYOUT, sub="local:alice")
        self.assertEqual(r.status_code, 200)
        saved = self._store.get_dashboard_prefs("local:alice")
        self.assertIn("panels",          saved)
        self.assertIn("overview_rows",   saved)
        self.assertIn("overview_panels", saved)
        self.assertIn("other",           saved)

    # ── DELETE ────────────────────────────────────────────────────────────────

    def test_delete_unauthenticated_returns_401(self):
        import unittest.mock as mock
        with mock.patch.object(ueba_auth, "current_user", return_value=None):
            r = self.client.delete("/api/dashboard/layout")
        self.assertEqual(r.status_code, 401)

    def test_delete_removes_saved_layout(self):
        self._store.set_dashboard_prefs("local:alice", SAMPLE_LAYOUT)
        r = self._delete(sub="local:alice")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])
        self.assertIsNone(self._store.get_dashboard_prefs("local:alice"))

    def test_delete_when_no_layout_still_returns_ok(self):
        r = self._delete(sub="local:alice")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])

    def test_delete_then_get_returns_null_layout(self):
        self._store.set_dashboard_prefs("local:alice", SAMPLE_LAYOUT)
        self._delete(sub="local:alice")
        r = self._get(sub="local:alice")
        body = r.get_json()
        self.assertIsNone(body["layout"])
        self.assertFalse(body["is_custom"])

    # ── Multi-analyst isolation ───────────────────────────────────────────────

    def test_alice_layout_does_not_affect_bob(self):
        layout_alice = dict(SAMPLE_LAYOUT)
        layout_alice["panels"] = [{"id": "tab-incidents", "visible": False}]
        self._put(layout_alice, sub="local:alice")

        r_bob = self._get(sub="local:bob")
        self.assertIsNone(r_bob.get_json()["layout"])

    def test_bob_reset_does_not_affect_alice(self):
        self._put(SAMPLE_LAYOUT, sub="local:alice")
        self._put(SAMPLE_LAYOUT, sub="local:bob")
        self._delete(sub="local:bob")

        r_alice = self._get(sub="local:alice")
        self.assertIsNotNone(r_alice.get_json()["layout"])


# ── VALID_PANEL_IDS whitelist check ──────────────────────────────────────────

class TestValidPanelIDsWhitelist(unittest.TestCase):

    def test_all_tab_panels_in_whitelist(self):
        for pid in TAB_PANELS:
            self.assertIn(pid, server.VALID_PANEL_IDS, f"missing: {pid}")

    def test_all_overview_rows_in_whitelist(self):
        for rid in OVERVIEW_ROWS:
            self.assertIn(rid, server.VALID_PANEL_IDS, f"missing: {rid}")

    def test_all_overview_panels_in_whitelist(self):
        for pid in OVERVIEW_PANELS:
            self.assertIn(pid, server.VALID_PANEL_IDS, f"missing: {pid}")

    def test_fp_panels_in_whitelist(self):
        for pid in ("fp-patterns", "fp-list"):
            self.assertIn(pid, server.VALID_PANEL_IDS, f"missing: {pid}")

    def test_ai_analyst_in_whitelist(self):
        self.assertIn("ov-ai-analyst", server.VALID_PANEL_IDS)


# ── Utility ───────────────────────────────────────────────────────────────────

class _nullctx:
    def __enter__(self): return self
    def __exit__(self, *a): pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
