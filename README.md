# Diff Review Forge

**A local-first code review workbench for unified diffs.**

Paste the output of git diff, git show or a pull request patch. Get a 0-100
review score across five axes, every finding backed by the exact line that
triggered it, the reason it matters and a concrete fix - then a prioritised plan
that says which fix buys back how many points.

No API keys. No network calls. No LLM. Nothing leaves your machine.

---

## Why it matters

Most code review tooling falls into one of two traps. Either it is a linter that
lists rules without telling you which ones actually matter on this change, or it
is a bot that posts a wall of generic comments nobody reads.

Diff Review Forge is built around one question:

> **If I am about to merge this diff, what should I look at first?**

Every finding carries the evidence that produced it, so you can disagree with it
in one glance. The score is not decoration - it is computed from severity
penalties on five axes, and **structural caps** stop a diff from scoring well by
skipping the hard part. A change with no tests, a leaked credential or a deleted
public function cannot buy its way to a high score by having tidy formatting.

## What it does

- **Parses the diff.** Understands git diff headers, new/deleted/renamed files,
  /dev/null, binary markers and multi-hunk patches. A patch pasted without the
  git header still parses.
- **Classifies every file.** Language, and whether it is source, test, config,
  docs, data, generated or vendored. Generated files are excluded from the noise.
- **Runs 62 rules** across five axes: correctness, security, performance, testing
  and maintainability.
- **Scores the diff 0-100** with an explainable model and named structural caps.
- **Re-weights the review** with six profiles (general, security audit, bug hunt,
  test adequacy, performance, API stability).
- **Finds breaking changes**: removed public functions, removed classes, removed
  HTTP routes, changed signatures and deleted source files.
- **Ranks the fixes.** The plan is ordered by the score each fix actually buys
  back, recomputed after every step.
- **Ranks the files.** A per-file risk score from churn, findings and file status,
  with a "review these first" hot-spot list.
- **Exports** a Markdown report, JSON or a findings CSV.
- **Keeps a run log** in SQLite with a 1-5 star self-rating.

## Quick start

    git clone https://github.com/jackson9413/diff-review-forge.git
    cd diff-review-forge
    python3 -m pip install -r requirements.txt
    python3 app.py
    # open http://127.0.0.1:5065

Paste a diff on the left, press **Review this diff**.

### Command line

    # human readable review
    python3 cli.py review change.diff

    # a specific lens
    python3 cli.py review change.diff --profile security_audit

    # machine readable
    python3 cli.py review change.diff --json
    python3 cli.py export change.diff --format csv --out findings.csv

    # the built-in examples
    python3 cli.py samples
    python3 cli.py samples --id secret_leak

## How the score works

**Axis score** = 100 - (sum of severity penalties on that axis)

| Severity | Penalty |
| --- | --- |
| Critical | 45 |
| High | 18 |
| Medium | 7 |
| Low | 2 |

**Overall score** = weighted average of the applicable axes, then the structural
caps are applied.

### Axes and default weights

| Axis | Default weight | What it looks at |
| --- | --- | --- |
| Correctness and logic | 30% | Swallowed exceptions, mutable defaults, off-by-one, naive datetimes, closures in loops, unreachable branches |
| Security | 25% | Hard-coded credentials, SQL and command injection, eval, unsafe deserialization, disabled TLS verification, permissive file modes, XSS, wildcard CORS |
| Performance | 15% | N+1 queries, HTTP calls in loops, list membership in a loop, sleeps in a request path, files opened in a loop, regexes compiled in a loop |
| Testing and verification | 20% | Missing tests for changed behaviour, assertions removed from a test, skipped tests, tests with no assertion, time-dependent tests |
| Maintainability | 10% | Long functions, deep nesting, TODOs, commented-out code, debug prints, wildcard imports, duplicated blocks, broken public APIs |

### Structural caps

The caps are the part that makes the score honest. They are named in the output
and in the report:

| Condition | Effect |
| --- | --- |
| A critical security finding | Security axis capped at 20 |
| A critical correctness finding | Correctness axis capped at 25 |
| Any critical finding | Overall capped at 40 |
| Two or more critical findings | Overall capped at 30 |
| Three or more high findings | Overall capped at 60 |
| Five or more high findings | Overall capped at 50 |
| Behaviour changed, no test changed | Testing axis capped at 30, overall capped at 62 |
| A public interface was broken | Maintainability capped at 40, overall capped at 55 |
| One file grew by 400 lines or more | Maintainability capped at 45, overall capped at 62 |

### Verdicts

| Score | Verdict |
| --- | --- |
| 90 and above | Ship it |
| 75 - 89 | Approve with comments |
| 60 - 74 | Needs changes |
| 40 - 59 | Do not merge yet |
| Below 40 | Dangerous |

### Profiles

| Profile | Focus |
| --- | --- |
| general | Balanced pass over every axis |
| security_audit | Injection, credentials, unsafe defaults |
| bug_hunt | Runtime logic errors, not style |
| test_adequacy | Does anything verify this change |
| performance | N+1 work, hot loops, blocking calls |
| api_stability | Public signatures, routes, deletions |

## The rules

**Security** - hardcoded_secret, provider_token, private_key_material,
sql_injection_risk, command_injection, eval_exec, unsafe_deserialization,
tls_verification_disabled, permissive_permissions, cors_wildcard, xss_inner_html,
debug_enabled, insecure_temp_file, weak_hash_for_password, insecure_random,
path_traversal

**Correctness** - bare_except, except_swallow, except_without_log,
mutable_default_argument, none_comparison, type_equality_check,
identity_comparison_literal, assert_in_production_code, off_by_one_length,
naive_datetime, loose_equality_js, return_in_finally, unreachable_else,
infinite_loop_risk, closure_in_loop, unhandled_promise, float_for_money

**Performance** - n_plus_one_query, http_call_in_loop, list_membership_in_loop,
string_concat_in_loop, regex_compiled_in_loop, file_open_in_loop, sort_in_loop,
sleep_in_request_path, sql_select_star

**Testing** - no_tests_changed, new_public_function_untested,
test_assertion_removed, test_skipped, weak_assertion, empty_test,
time_dependent_test, sleep_in_test

**Maintainability** - todo_marker_left, commented_out_code, debug_print_left,
debugger_statement, wildcard_import, global_statement, long_line, deep_nesting,
long_function, magic_time_constant, duplicated_code_block, generated_file_changed,
large_file_growth, noisy_mechanical_diff, public_symbol_removed,
public_class_removed, route_removed, signature_changed, file_deleted

## Built-in samples

Six scenarios ship with the app. They double as calibration cases.

| Sample | Score | Verdict | What it proves |
| --- | --- | --- | --- |
| clean_pull_request | 100.0 | Ship it | A clean change with a test produces zero findings |
| secret_leak | 30.0 | Dangerous | Four criticals: two hard-coded credentials, a live-looking token and a session secret |
| n_plus_one_regression | 62.0 | Needs changes | A database call inside a loop, plus a sleep in the request path |
| bugfix_without_tests | 60.0 | Needs changes | A swallowed TypeError, a mutable default argument and no test |
| breaking_api_rename | 55.0 | Do not merge yet | A renamed public function, a removed route and a deleted module |
| refactor_sweep | 62.0 | Needs changes | A TODO, commented-out code, a debug log and an untested new function |

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | /api/health | Service, version, rule count, profiles |
| GET | /api/profiles | Profile list and weights |
| GET | /api/samples | The six built-in samples |
| GET | /api/samples/<id> | One sample diff |
| POST | /api/review | Review a diff: {"diff": "...", "profile": "general"} |
| POST | /api/export | Export {"diff": "...", "format": "md" or "json" or "csv"} |
| GET/POST | /api/runs | List or save runs |
| GET/PATCH/DELETE | /api/runs/<id> | Read, rate or delete a run |

Example:

    curl -s -X POST http://127.0.0.1:5065/api/review \
      -H 'Content-Type: application/json' \
      -d '{"diff": "...", "profile": "security_audit"}'

## Project layout

    diffparse.py    unified diff parser, file classification
    rules.py        62 rules, line level and block level
    engine.py       scoring, caps, profiles, fix plan, risk
    exporters.py    Markdown / JSON / CSV output
    storage.py      SQLite run log
    app.py          Flask app and REST API
    cli.py          command line interface
    samples.py      the six built-in sample diffs
    static/         dark vanilla JS front end
    tests/          70 unit, API and frontend contract tests

## Tests

    python3 -m unittest discover -s tests

70 tests: the parser (counts, line numbers, new and deleted files, renames,
non-diff input), every rule family, the scoring model and its caps, profile
weighting, the fix plan, the REST API (including export formats and the run
log) and a frontend contract check that keeps static/app.js in step with the
API response shape.

## Privacy

Everything runs locally. The diff never leaves the machine: there is no
telemetry, no outbound request and no model provider in the loop. The run log is
a local SQLite file (runs.db, override with DIFF_REVIEW_DB).

## License

MIT.

## Domain note

Built for the **developer tools / code review** slot. It reviews a patch before
it is merged - it is not a linter, not a debugger, not a CI runner and not a
project tracker.
