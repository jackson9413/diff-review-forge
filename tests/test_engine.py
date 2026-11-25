"""Engine tests for Diff Review Forge."""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import engine  # noqa: E402
from diffparse import classify_category, parse_diff  # noqa: E402
from samples import get_sample, list_samples  # noqa: E402


def make_diff(path, body, headers=""):
    old = len([line for line in body if not line.startswith("+")])
    new = len([line for line in body if not line.startswith("-")])
    header = "@@ -1," + str(old) + " +1," + str(new) + " @@"
    return (
        "diff --git a/"
        + path
        + " b/"
        + path
        + "\n"
        + headers
        + "--- a/"
        + path
        + "\n+++ b/"
        + path
        + "\n"
        + header
        + "\n"
        + "\n".join(body)
        + "\n"
    )


def rules_in(result):
    return [f["rule"] for f in result["findings"]]


class ParserTests(unittest.TestCase):
    def test_counts_files_and_lines(self):
        diff = parse_diff(
            make_diff(
                "app/x.py",
                [" ctx", "-old line", "+new line", "+second new", " more ctx"],
            )
        )
        self.assertEqual(len(diff.files), 1)
        self.assertEqual(diff.files[0].additions, 2)
        self.assertEqual(diff.files[0].deletions, 1)
        self.assertEqual(diff.additions, 2)
        self.assertEqual(diff.deletions, 1)

    def test_new_file_mode(self):
        diff = parse_diff(
            make_diff("app/new.py", ["+one", "+two"], headers="new file mode 100644\n")
        )
        self.assertEqual(diff.files[0].status, "added")

    def test_deleted_file_mode(self):
        diff = parse_diff(
            make_diff("app/gone.py", ["-one", "-two"], headers="deleted file mode 100644\n")
        )
        self.assertEqual(diff.files[0].status, "deleted")

    def test_line_numbers_track_the_new_file(self):
        diff = parse_diff(make_diff("app/x.py", [" ctx", "+added", " ctx2"]))
        added = diff.files[0].added_lines
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0].new_no, 2)

    def test_language_and_category(self):
        diff = parse_diff(make_diff("tests/test_x.py", ["+x = 1"]))
        self.assertEqual(diff.files[0].language, "python")
        self.assertEqual(diff.files[0].category, "test")
        self.assertEqual(diff.test_files and diff.test_files[0].path, "tests/test_x.py")

    def test_vendor_and_generated_are_skipped(self):
        self.assertEqual(classify_category("node_modules/left-pad/index.js"), "generated")
        self.assertEqual(classify_category("web/app.min.js"), "generated")
        self.assertEqual(classify_category("README.md"), "docs")
        self.assertEqual(classify_category("app/config.yaml"), "config")

    def test_not_a_diff(self):
        diff = parse_diff("just some prose, no patch here")
        self.assertEqual(len(diff.files), 0)
        self.assertTrue(diff.warnings)

    def test_empty_input(self):
        diff = parse_diff("")
        self.assertEqual(len(diff.files), 0)


class SecurityRuleTests(unittest.TestCase):
    def test_hardcoded_secret(self):
        result = engine.review_diff(make_diff("app/config.py", ['+API_KEY = "sk-abcdef123456"']))
        self.assertIn("hardcoded_secret", rules_in(result))

    def test_secret_underscore_name(self):
        result = engine.review_diff(
            make_diff("app/config.py", ['+DB_PASSWORD = "Sup3rS3cret"'])
        )
        self.assertIn("hardcoded_secret", rules_in(result))

    def test_env_var_is_not_a_secret(self):
        result = engine.review_diff(
            make_diff("app/config.py", ['+API_KEY = os.environ["API_KEY"]'])
        )
        self.assertNotIn("hardcoded_secret", rules_in(result))

    def test_sql_injection(self):
        result = engine.review_diff(
            make_diff(
                "app/db.py",
                ['+cursor.execute("SELECT * FROM users WHERE id = " + user_id)'],
            )
        )
        self.assertIn("sql_injection_risk", rules_in(result))

    def test_eval(self):
        result = engine.review_diff(make_diff("app/run.py", ["+value = eval(payload)"]))
        self.assertIn("eval_exec", rules_in(result))

    def test_tls_verification(self):
        result = engine.review_diff(
            make_diff("app/http.py", ["+requests.get(url, verify=False)"])
        )
        self.assertIn("tls_verification_disabled", rules_in(result))

    def test_shell_true(self):
        result = engine.review_diff(
            make_diff("app/run.py", ["+subprocess.run(cmd, shell=True)"])
        )
        self.assertIn("command_injection", rules_in(result))


class CorrectnessRuleTests(unittest.TestCase):
    def test_bare_except(self):
        result = engine.review_diff(make_diff("app/x.py", ["+try:", "+    work()", "+except:"]))
        self.assertIn("bare_except", rules_in(result))

    def test_except_pass(self):
        result = engine.review_diff(
            make_diff("app/x.py", ["+try:", "+    work()", "+except ValueError:", "+    pass"])
        )
        self.assertIn("except_swallow", rules_in(result))

    def test_mutable_default(self):
        result = engine.review_diff(make_diff("app/x.py", ["+def f(items=[]):"]))
        self.assertIn("mutable_default_argument", rules_in(result))

    def test_none_comparison(self):
        result = engine.review_diff(make_diff("app/x.py", ["+if value == None:"]))
        self.assertIn("none_comparison", rules_in(result))

    def test_return_in_finally(self):
        result = engine.review_diff(
            make_diff("app/x.py", ["+try:", "+    work()", "+finally:", "+    return 1"])
        )
        self.assertIn("return_in_finally", rules_in(result))


class PerformanceRuleTests(unittest.TestCase):
    def test_n_plus_one(self):
        result = engine.review_diff(
            make_diff(
                "app/api.py",
                [
                    "+for order in orders:",
                    "+    product = session.query(Product).get(order.product_id)",
                    "+    total += product.price",
                ],
            )
        )
        self.assertIn("n_plus_one_query", rules_in(result))

    def test_http_in_loop(self):
        result = engine.review_diff(
            make_diff(
                "app/api.py",
                ["+for item in items:", "+    data = requests.get(item.url)"],
            )
        )
        self.assertIn("http_call_in_loop", rules_in(result))

    def test_sleep_in_request_path(self):
        result = engine.review_diff(make_diff("app/api.py", ["+time.sleep(0.5)"]))
        self.assertIn("sleep_in_request_path", rules_in(result))


class TestingRuleTests(unittest.TestCase):
    def test_skipped_test(self):
        result = engine.review_diff(
            make_diff("tests/test_x.py", ["+@pytest.mark.skip", "+def test_a():", "+    pass"])
        )
        self.assertIn("test_skipped", rules_in(result))

    def test_removed_assertion(self):
        result = engine.review_diff(
            make_diff("tests/test_x.py", [" ctx", "-    assert result == 3", " ctx2"])
        )
        self.assertIn("test_assertion_removed", rules_in(result))

    def test_no_tests_for_source_change(self):
        result = engine.review_diff(
            make_diff("app/x.py", ["+def handler(request):", "+    return 1"])
        )
        self.assertIn("no_tests_changed", rules_in(result))

    def test_tests_present_means_no_gap_finding(self):
        diff = make_diff("app/x.py", ["+def handler(request):", "+    return 1"]) + make_diff(
            "tests/test_x.py", ["+def test_handler():", "+    assert handler(None) == 1"]
        )
        result = engine.review_diff(diff)
        self.assertNotIn("no_tests_changed", rules_in(result))


class MaintainabilityRuleTests(unittest.TestCase):
    def test_todo(self):
        result = engine.review_diff(make_diff("app/x.py", ["+    # TODO: handle the empty case"]))
        self.assertIn("todo_marker_left", rules_in(result))

    def test_commented_out_code(self):
        result = engine.review_diff(make_diff("app/x.py", ["+    # def old_helper(a, b):"]))
        self.assertIn("commented_out_code", rules_in(result))

    def test_debug_print(self):
        result = engine.review_diff(make_diff("web/app.js", ["+  console.log(\"here\", id);"]))
        self.assertIn("debug_print_left", rules_in(result))

    def test_removed_public_symbol(self):
        result = engine.review_diff(
            make_diff("app/api.py", [" ctx", "-def get_user(user_id):", " ctx2"])
        )
        self.assertIn("public_symbol_removed", rules_in(result))

    def test_deleted_file(self):
        result = engine.review_diff(
            make_diff("app/legacy.py", ["-def x():", "-    return 1"], headers="deleted file mode 100644\n")
        )
        self.assertIn("file_deleted", rules_in(result))

    def test_signature_change(self):
        result = engine.review_diff(
            make_diff(
                "app/api.py",
                [" ctx", "-def get_user(user_id):", "+def get_user(user_id, include_org=False):", " ctx2"],
            )
        )
        self.assertIn("signature_changed", rules_in(result))


class ScoringTests(unittest.TestCase):
    def test_clean_diff_scores_high(self):
        diff = make_diff("app/x.py", ["+def add(a, b):", "+    return a + b"]) + make_diff(
            "tests/test_x.py", ["+def test_add():", "+    assert add(1, 2) == 3"]
        )
        result = engine.review_diff(diff)
        self.assertGreaterEqual(result["score"]["overall"], 90)
        self.assertEqual(result["score"]["verdict"], "ship_it")

    def test_secret_caps_the_security_axis(self):
        result = engine.review_diff(
            make_diff("app/config.py", ['+API_KEY = "sk-abcdef1234567890"'])
        )
        axes = {a["key"]: a for a in result["score"]["axes"]}
        self.assertLessEqual(axes["security"]["score"], 20)
        self.assertLessEqual(result["score"]["overall"], 40)

    def test_missing_tests_caps_the_testing_axis(self):
        result = engine.review_diff(make_diff("app/x.py", ["+def handler():", "+    return 1"]))
        axes = {a["key"]: a for a in result["score"]["axes"]}
        self.assertEqual(axes["testing"]["score"], 30)
        self.assertLessEqual(result["score"]["overall"], 62)

    def test_breaking_change_caps_maintainability(self):
        result = engine.review_diff(
            make_diff("app/api.py", [" ctx", "-def get_user(user_id):", " ctx2"])
        )
        axes = {a["key"]: a for a in result["score"]["axes"]}
        self.assertEqual(axes["maintainability"]["score"], 40)
        self.assertLessEqual(result["score"]["overall"], 55)
        self.assertTrue(result["breaking_changes"])

    def test_profiles_change_the_weighting(self):
        diff = make_diff(
            "app/api.py",
            ["+for item in items:", "+    data = requests.get(item.url)"],
        ) + make_diff(
            "tests/test_api.py",
            ["+def test_fetch():", "+    assert True"],
        )
        general = engine.review_diff(diff, profile="general")["score"]["overall"]
        perf = engine.review_diff(diff, profile="performance")["score"]["overall"]
        self.assertLess(perf, general)

    def test_unknown_profile_falls_back(self):
        result = engine.review_diff(make_diff("app/x.py", ["+x = 1"]), profile="nope")
        self.assertEqual(result["meta"]["profile"], "general")

    def test_plan_is_ordered_by_score(self):
        result = engine.review_diff(
            make_diff("app/x.py", ["+API_KEY = \"sk-abcdef123456\"", "+import os"])
        )
        plan = result["plan"]
        self.assertTrue(plan)
        scores = [step["score_after"] for step in plan]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_summary_is_prose(self):
        result = engine.review_diff(make_diff("app/x.py", ["+x = 1"]))
        self.assertIsInstance(result["summary"], str)
        self.assertGreater(len(result["summary"]), 20)

    def test_result_shape(self):
        result = engine.review_diff(make_diff("app/x.py", ["+x = 1"]))
        for key in ("meta", "score", "findings", "files", "hotspots", "breaking_changes",
                    "coverage", "plan", "summary"):
            self.assertIn(key, result)
        self.assertIn("overall", result["score"])
        self.assertIn("axes", result["score"])
        self.assertIn("caps", result["score"])


class SampleTests(unittest.TestCase):
    def test_all_samples_review(self):
        for meta in list_samples():
            sample = get_sample(meta["id"])
            self.assertIsNotNone(sample)
            result = engine.review_diff(sample["diff"], profile=meta["profile"])
            self.assertEqual(result["meta"]["files"] >= 1, True)

    def test_clean_sample_is_clean(self):
        result = engine.review_diff(get_sample("clean_pull_request")["diff"])
        self.assertEqual(result["score"]["counts"]["total"], 0)
        self.assertEqual(result["score"]["overall"], 100.0)

    def test_secret_sample_is_dangerous(self):
        result = engine.review_diff(get_sample("secret_leak")["diff"], profile="security_audit")
        self.assertEqual(result["score"]["verdict"], "dangerous")
        self.assertGreaterEqual(result["score"]["counts"]["critical"], 3)

    def test_breaking_sample_reports_breaking_changes(self):
        result = engine.review_diff(get_sample("breaking_api_rename")["diff"])
        self.assertTrue(result["breaking_changes"])


if __name__ == "__main__":
    unittest.main()
