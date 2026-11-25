"""Frontend contract tests.

The browser app talks to the API with plain JSON, so the contract between the
two is a set of field names. These tests make sure the HTML, the CSS and the
JavaScript still line up with what the API returns.
"""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

STATIC = os.path.join(ROOT, "static")


def read(name):
    with open(os.path.join(STATIC, name), "r", encoding="utf-8") as handle:
        return handle.read()


class StaticFileTests(unittest.TestCase):
    def test_files_exist(self):
        for name in ("index.html", "styles.css", "app.js"):
            self.assertTrue(os.path.exists(os.path.join(STATIC, name)), name)

    def test_html_has_mount_points(self):
        html = read("index.html")
        for element_id in (
            "diff-input",
            "profile",
            "review-btn",
            "clear-btn",
            "sample-list",
            "results",
            "verdict-banner",
            "summary-text",
            "axis-bars",
            "tab-findings",
            "tab-files",
            "tab-plan",
            "tab-coverage",
            "tab-runs",
            "run-title",
            "run-rating",
            "save-run",
        ):
            self.assertIn('id="' + element_id + '"', html)

    def test_html_has_tabs(self):
        html = read("index.html")
        for tab in ("findings", "files", "plan", "coverage", "runs"):
            self.assertIn('data-tab="' + tab + '"', html)

    def test_javascript_calls_the_api(self):
        js = read("app.js")
        for endpoint in (
            "/api/health",
            "/api/profiles",
            "/api/samples",
            "/api/review",
            "/api/export",
            "/api/runs",
        ):
            self.assertIn(endpoint, js)

    def test_javascript_reads_the_result_fields(self):
        js = read("app.js")
        for field in (
            "findings",
            "score",
            "verdict_label",
            "overall",
            "axes",
            "caps",
            "files",
            "plan",
            "coverage",
            "breaking_changes",
            "risk_reasons",
            "hotspots",
        ):
            self.assertTrue(field in js, "app.js does not use the field " + field)

    def test_javascript_has_no_syntax_errors(self):
        js = read("app.js")
        self.assertTrue(js.count("{") == js.count("}"))
        self.assertTrue(js.count("(") == js.count(")"))

    def test_css_defines_the_dark_theme(self):
        css = read("styles.css")
        self.assertIn("--bg", css)
        self.assertIn(".finding", css)
        self.assertIn(".verdict", css)
        self.assertIn(".axis-row", css)


class ApiContractTests(unittest.TestCase):
    def test_result_keys_used_by_the_frontend(self):
        import engine
        from samples import get_sample

        result = engine.review_diff(get_sample("refactor_sweep")["diff"])
        expected = {
            "meta": ["files", "additions", "deletions", "languages", "profile_label", "reviewed_at"],
            "score": ["overall", "verdict", "verdict_label", "verdict_note", "axes", "caps", "counts"],
            "coverage": ["source_files", "test_files", "note"],
        }
        for section, keys in expected.items():
            for key in keys:
                self.assertIn(key, result[section], section + "." + key)
        for axis in result["score"]["axes"]:
            for key in ("key", "label", "score", "weight", "applicable", "findings", "cap"):
                self.assertIn(key, axis)
        for finding in result["findings"]:
            for key in ("id", "rule", "axis", "severity", "title", "path", "line", "evidence", "why", "fix"):
                self.assertIn(key, finding)
        for row in result["files"]:
            for key in ("path", "status", "language", "category", "additions", "deletions", "risk", "risk_reasons"):
                self.assertIn(key, row)
        for step in result["plan"]:
            for key in ("step", "rule", "axis", "count", "title", "action", "gain", "score_after", "paths"):
                self.assertIn(key, step)


if __name__ == "__main__":
    unittest.main()
