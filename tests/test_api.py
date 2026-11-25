"""API tests for Diff Review Forge."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Point the run log at a temporary database before the app imports storage.
os.environ["DIFF_REVIEW_DB"] = os.path.join(tempfile.mkdtemp(prefix="diff-review-tests-"), "runs.db")

import app as application  # noqa: E402
from samples import get_sample  # noqa: E402

application.app.config["TESTING"] = True
client = application.app.test_client()


class HealthAndMetaTests(unittest.TestCase):
    def test_health(self):
        resp = client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertGreater(data["rule_count"], 40)
        self.assertIn("general", data["profiles"])

    def test_profiles(self):
        resp = client.get("/api/profiles")
        self.assertEqual(resp.status_code, 200)
        profiles = resp.get_json()["profiles"]
        self.assertTrue(profiles)
        for profile in profiles:
            self.assertIn("weights", profile)
            self.assertEqual(sum(profile["weights"].values()), 100)

    def test_index_page(self):
        resp = client.get("/")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("Diff Review Forge", body)


class SampleTests(unittest.TestCase):
    def test_list(self):
        resp = client.get("/api/samples")
        self.assertEqual(resp.status_code, 200)
        samples = resp.get_json()["samples"]
        self.assertEqual(len(samples), 6)

    def test_single_sample(self):
        resp = client.get("/api/samples/clean_pull_request")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("diff --git", data["diff"])

    def test_unknown_sample(self):
        resp = client.get("/api/samples/nope")
        self.assertEqual(resp.status_code, 404)


class ReviewTests(unittest.TestCase):
    def test_review(self):
        diff = get_sample("secret_leak")["diff"]
        resp = client.post("/api/review", json={"diff": diff, "profile": "security_audit"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("score", data)
        self.assertIn("findings", data)
        self.assertGreater(data["score"]["counts"]["critical"], 0)

    def test_review_requires_a_diff(self):
        resp = client.post("/api/review", json={"diff": "   "})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())

    def test_review_rejects_unknown_profile(self):
        resp = client.post("/api/review", json={"diff": "x", "profile": "nope"})
        self.assertEqual(resp.status_code, 400)

    def test_review_of_rubbish(self):
        resp = client.post("/api/review", json={"diff": "not a patch at all"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["meta"]["files"], 0)
        self.assertTrue(data["meta"]["warnings"])


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.diff = get_sample("n_plus_one_regression")["diff"]

    def test_markdown(self):
        resp = client.post("/api/export", json={"diff": self.diff, "format": "md"})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("# Code review report", body)
        self.assertIn("## Scorecard", body)

    def test_json(self):
        resp = client.post("/api/export", json={"diff": self.diff, "format": "json"})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn('"findings"', body)

    def test_csv(self):
        resp = client.post("/api/export", json={"diff": self.diff, "format": "csv"})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertTrue(body.splitlines()[0].startswith("id,severity,axis"))

    def test_bad_format(self):
        resp = client.post("/api/export", json={"diff": self.diff, "format": "pdf"})
        self.assertEqual(resp.status_code, 400)


class RunLogTests(unittest.TestCase):
    def test_create_list_update_delete(self):
        diff = get_sample("clean_pull_request")["diff"]
        resp = client.post(
            "/api/runs", json={"diff": diff, "profile": "general", "title": "my review", "rating": 4}
        )
        self.assertEqual(resp.status_code, 201)
        run_id = resp.get_json()["id"]

        listing = client.get("/api/runs").get_json()["runs"]
        self.assertTrue(any(r["id"] == run_id for r in listing))

        single = client.get("/api/runs/" + str(run_id))
        self.assertEqual(single.status_code, 200)
        self.assertEqual(single.get_json()["rating"], 4)

        patched = client.patch("/api/runs/" + str(run_id), json={"rating": 5, "notes": "good"})
        self.assertEqual(patched.status_code, 200)
        self.assertEqual(patched.get_json()["rating"], 5)

        self.assertEqual(client.delete("/api/runs/" + str(run_id)).status_code, 200)
        self.assertEqual(client.get("/api/runs/" + str(run_id)).status_code, 404)

    def test_bad_rating(self):
        diff = get_sample("clean_pull_request")["diff"]
        resp = client.post("/api/runs", json={"diff": diff, "rating": 9})
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
