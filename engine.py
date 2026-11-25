"""Diff Review Forge - review engine.

Turns a unified diff into a scored, prioritised code review:

    diff text -> parsed files -> findings -> 0-100 scorecard -> fix plan

The scoring model is deliberately simple and explainable:

    axis score = 100 - (sum of severity penalties for findings on that axis)
    overall    = weighted average of the applicable axis scores
    caps       = structural limits that stop a diff from scoring well by
                 skipping the hard part (no tests, a hard-coded secret,
                 a deleted public function)

No API keys, no network calls, no LLM.
"""

from __future__ import annotations

import datetime
from typing import Dict, List, Optional

from diffparse import ENGINE_VERSION, DiffFile, DiffSet, parse_diff
from rules import (
    AXES,
    AXIS_LABELS,
    Finding,
    SEVERITY_LABEL,
    SEVERITY_ORDER,
    SEVERITY_PENALTY,
    all_findings,
)

PROFILES: Dict[str, dict] = {
    "general": {
        "label": "General review",
        "blurb": "Balanced pass over every axis. The default for a pull request.",
        "weights": {
            "correctness": 30,
            "security": 25,
            "performance": 15,
            "testing": 20,
            "maintainability": 10,
        },
    },
    "security_audit": {
        "label": "Security audit",
        "blurb": "Injection, credentials, unsafe defaults and unsafe deserialization.",
        "weights": {
            "correctness": 15,
            "security": 55,
            "performance": 5,
            "testing": 15,
            "maintainability": 10,
        },
    },
    "bug_hunt": {
        "label": "Bug hunt",
        "blurb": "Logic errors that will show up at runtime, not style.",
        "weights": {
            "correctness": 45,
            "security": 15,
            "performance": 15,
            "testing": 15,
            "maintainability": 10,
        },
    },
    "test_adequacy": {
        "label": "Test adequacy",
        "blurb": "Does anything verify this change? Weak, skipped and missing tests.",
        "weights": {
            "correctness": 20,
            "security": 10,
            "performance": 5,
            "testing": 50,
            "maintainability": 15,
        },
    },
    "performance": {
        "label": "Performance",
        "blurb": "N+1 work, hot loops, blocking calls and wasted allocation.",
        "weights": {
            "correctness": 20,
            "security": 5,
            "performance": 50,
            "testing": 10,
            "maintainability": 15,
        },
    },
    "api_stability": {
        "label": "API stability",
        "blurb": "Public signatures, removed symbols, routes and file deletions.",
        "weights": {
            "correctness": 25,
            "security": 15,
            "performance": 5,
            "testing": 10,
            "maintainability": 45,
        },
    },
}

VERDICTS = [
    {"min": 90, "key": "ship_it", "label": "Ship it", "note": "Nothing that needs fixing before merge."},
    {"min": 75, "key": "approve_with_comments", "label": "Approve with comments", "note": "Mergeable, but address the comments."},
    {"min": 60, "key": "needs_changes", "label": "Needs changes", "note": "Fix the high and critical findings first."},
    {"min": 40, "key": "do_not_merge", "label": "Do not merge yet", "note": "This diff carries real risk."},
    {"min": 0, "key": "dangerous", "label": "Dangerous", "note": "Do not merge. Serious problems in this diff."},
]

RISK_SEVERITY = {"critical": 40, "high": 20, "medium": 8, "low": 3}


def _verdict_for(score: float) -> dict:
    for band in VERDICTS:
        if score >= band["min"]:
            return band
    return VERDICTS[-1]


def _applicable_axes(diff: DiffSet, profile: str) -> List[str]:
    weights = PROFILES[profile]["weights"]
    axes = [a for a in AXES if weights.get(a)]
    if not diff.source_files and not diff.test_files:
        # Documentation, config or data only: there is no behaviour to test.
        axes = [a for a in axes if a != "testing"]
    return axes


def _compute_score(findings: List[Finding], diff: DiffSet, profile: str) -> dict:
    weights = PROFILES[profile]["weights"]
    applicable = _applicable_axes(diff, profile)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    axis_counts: Dict[str, Dict[str, int]] = {
        a: {"critical": 0, "high": 0, "medium": 0, "low": 0} for a in AXES
    }
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        axis_counts[f.axis][f.severity] += 1

    axis_scores: Dict[str, float] = {}
    for axis in AXES:
        penalty = 0.0
        for sev, n in axis_counts[axis].items():
            penalty += SEVERITY_PENALTY[sev] * n
        axis_scores[axis] = round(max(0.0, 100.0 - penalty), 1)

    caps: List[dict] = []

    def cap_axis(axis: str, limit: float, reason: str) -> None:
        if axis_scores[axis] > limit:
            caps.append({"scope": axis, "limit": limit, "reason": reason})
            axis_scores[axis] = limit

    def cap_overall(limit: float, reason: str) -> None:
        caps.append({"scope": "overall", "limit": limit, "reason": reason})

    breaking = _breaking_changes(findings)
    source_changed = bool(diff.source_files)
    tests_changed = bool(diff.test_files)
    mega = any(f.additions >= 400 for f in diff.files)

    if axis_counts["security"]["critical"]:
        cap_axis("security", 20.0, "A critical security finding caps the security axis.")
    if axis_counts["correctness"]["critical"]:
        cap_axis("correctness", 25.0, "A critical correctness finding caps the correctness axis.")
    if counts["critical"]:
        cap_overall(40.0, "At least one critical finding caps the overall score.")
    if counts["critical"] >= 2:
        cap_overall(30.0, "Two or more critical findings cap the overall score.")
    if counts["high"] >= 5:
        cap_overall(50.0, "Five or more high findings cap the overall score.")
    elif counts["high"] >= 3:
        cap_overall(60.0, "Three or more high findings cap the overall score.")
    if axis_counts["security"]["high"] >= 2:
        cap_axis("security", 40.0, "Two or more high security findings cap the security axis.")
    if source_changed and not tests_changed:
        cap_axis("testing", 30.0, "Behaviour changed with no test changes in this diff.")
        cap_overall(62.0, "A change with no tests cannot score above 62.")
    if breaking:
        cap_axis("maintainability", 40.0, "A public interface was broken in this diff.")
        cap_overall(55.0, "Breaking a public interface caps the overall score.")
    if mega:
        cap_axis("maintainability", 45.0, "A single file grew by 400 lines or more.")
        cap_overall(62.0, "A 400 line change in one file caps the overall score.")

    total_weight = sum(weights.get(a, 0) for a in applicable) or 1
    overall = sum(axis_scores[a] * weights.get(a, 0) for a in applicable) / total_weight

    overall = min(overall, 100.0)
    for cap in caps:
        if cap["scope"] == "overall":
            overall = min(overall, cap["limit"])

    overall = round(max(0.0, overall), 1)

    axis_rows = []
    for axis in AXES:
        row = {
            "key": axis,
            "label": AXIS_LABELS[axis],
            "score": axis_scores[axis],
            "weight": weights.get(axis, 0),
            "applicable": axis in applicable,
            "findings": sum(axis_counts[axis].values()),
            "critical": axis_counts[axis]["critical"],
            "high": axis_counts[axis]["high"],
            "medium": axis_counts[axis]["medium"],
            "low": axis_counts[axis]["low"],
            "cap": next((c["limit"] for c in caps if c["scope"] == axis), None),
        }
        axis_rows.append(row)

    band = _verdict_for(overall)
    return {
        "overall": overall,
        "verdict": band["key"],
        "verdict_label": band["label"],
        "verdict_note": band["note"],
        "axes": axis_rows,
        "caps": caps,
        "counts": {
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "total": len(findings),
        },
    }


def _breaking_changes(findings: List[Finding]) -> List[dict]:
    out = []
    for f in findings:
        if f.rule in (
            "public_symbol_removed",
            "public_class_removed",
            "route_removed",
            "signature_changed",
            "file_deleted",
        ):
            out.append(
                {
                    "kind": f.rule,
                    "path": f.path,
                    "line": f.line,
                    "title": f.title,
                    "detail": f.why,
                    "severity": f.severity,
                }
            )
    return out


def _file_risk(file: DiffFile, findings: List[Finding]) -> dict:
    reasons: List[str] = []
    score = 0.0
    churn = file.additions + file.deletions
    if churn:
        score += min(30.0, churn / 6.0)
        if churn >= 120:
            reasons.append("large diff (" + str(churn) + " changed lines)")
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.path != file.path:
            continue
        counts[f.severity] = counts.get(f.severity, 0) + 1
        score += RISK_SEVERITY.get(f.severity, 0)
    if counts["critical"]:
        reasons.append(str(counts["critical"]) + " critical finding(s)")
    if counts["high"]:
        reasons.append(str(counts["high"]) + " high finding(s)")
    if file.status == "deleted":
        score += 15
        reasons.append("file deleted")
    if file.category == "source" and file.additions >= 150:
        score += 10
        reasons.append("big source file")
    if file.is_generated:
        score = max(0.0, score - 15)
        reasons.append("generated or vendored file")
    return {
        "risk": round(min(100.0, score), 1),
        "reasons": reasons,
        "counts": counts,
    }


def _build_plan(findings: List[Finding], diff: DiffSet, profile: str) -> List[dict]:
    groups: Dict[str, List[Finding]] = {}
    for f in findings:
        groups.setdefault(f.rule, []).append(f)

    def group_sort_key(item):
        rule_id, group = item
        worst = min(SEVERITY_ORDER[f.severity] for f in group)
        penalty = sum(SEVERITY_PENALTY[f.severity] for f in group)
        return (worst, -penalty)

    plan = []
    current = list(findings)
    current_score = _compute_score(current, diff, profile)["overall"]
    for idx, (rule_id, group) in enumerate(sorted(groups.items(), key=group_sort_key), start=1):
        remaining = [f for f in current if f.rule != rule_id]
        after = _compute_score(remaining, diff, profile)["overall"]
        gain = round(after - current_score, 1)
        sample = group[0]
        plan.append(
            {
                "step": idx,
                "rule": rule_id,
                "axis": sample.axis,
                "axis_label": AXIS_LABELS.get(sample.axis, sample.axis),
                "count": len(group),
                "severity": min((f.severity for f in group), key=lambda s: SEVERITY_ORDER[s]),
                "title": sample.title,
                "action": sample.fix,
                "paths": sorted({f.path for f in group})[:4],
                "gain": gain,
                "score_after": after,
            }
        )
        current = remaining
        current_score = after
    return plan


def _summary(score: dict, findings: List[Finding], diff: DiffSet) -> str:
    counts = score["counts"]
    parts = []
    parts.append(
        "Reviewed "
        + str(len(diff.files))
        + " file(s), "
        + str(diff.additions)
        + " addition(s) and "
        + str(diff.deletions)
        + " deletion(s)."
    )
    if counts["total"] == 0:
        parts.append("No problems found by the rule set - this diff looks clean.")
        return " ".join(parts)
    parts.append(
        "Found "
        + str(counts["critical"])
        + " critical, "
        + str(counts["high"])
        + " high, "
        + str(counts["medium"])
        + " medium and "
        + str(counts["low"])
        + " low finding(s)."
    )
    parts.append("Verdict: " + score["verdict_label"] + " (" + str(score["overall"]) + "/100).")
    if score["caps"]:
        parts.append("Structural caps applied: " + "; ".join(c["reason"] for c in score["caps"]) + ".")
    if findings:
        worst = findings[0]
        parts.append("Start with: " + worst.title + ".")
    return " ".join(parts)


def review_diff(diff_text: str, profile: str = "general") -> dict:
    """Review a unified diff and return the full report as a plain dict."""
    if profile not in PROFILES:
        profile = "general"

    diff = parse_diff(diff_text or "")
    findings = all_findings(diff)

    findings.sort(
        key=lambda f: (
            SEVERITY_ORDER[f.severity],
            AXES.index(f.axis) if f.axis in AXES else 9,
            f.path,
            f.line or 0,
        )
    )

    score = _compute_score(findings, diff, profile)

    per_file: Dict[str, List[Finding]] = {}
    for f in findings:
        per_file.setdefault(f.path, []).append(f)

    file_rows = []
    for file in diff.files:
        file_findings_list = per_file.get(file.path, [])
        risk = _file_risk(file, file_findings_list)
        file_rows.append(
            {
                "path": file.path,
                "status": file.status,
                "language": file.language,
                "category": file.category,
                "generated": file.is_generated,
                "additions": file.additions,
                "deletions": file.deletions,
                "estimated_length": file.estimated_length,
                "findings": len(file_findings_list),
                "risk": risk["risk"],
                "risk_reasons": risk["reasons"],
                "counts": risk["counts"],
            }
        )
    file_rows.sort(key=lambda r: (-r["risk"], r["path"]))

    hotspots = [row for row in file_rows[:5] if row["findings"] or row["risk"] >= 15]

    breaking = _breaking_changes(findings)

    plan = _build_plan(findings, diff, profile)

    result = {
        "meta": {
            "engine_version": ENGINE_VERSION,
            "profile": profile,
            "profile_label": PROFILES[profile]["label"],
            "profile_blurb": PROFILES[profile]["blurb"],
            "files": len(diff.files),
            "additions": diff.additions,
            "deletions": diff.deletions,
            "languages": diff.languages,
            "categories": diff.categories(),
            "warnings": diff.warnings,
            "reviewed_at": datetime.datetime.now(datetime.timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        },
        "score": score,
        "findings": [f.to_dict(i + 1) for i, f in enumerate(findings)],
        "files": file_rows,
        "hotspots": hotspots,
        "breaking_changes": breaking,
        "coverage": {
            "source_files": len(diff.source_files),
            "test_files": len(diff.test_files),
            "tests_changed": bool(diff.test_files),
            "note": (
                "No test file changed in this diff."
                if diff.source_files and not diff.test_files
                else (
                    "Tests changed alongside the code."
                    if diff.test_files
                    else "No source or test file changed."
                )
            ),
        },
        "plan": plan,
        "summary": _summary(score, findings, diff),
    }
    return result


def analyse_text(diff_text: str, profile: str = "general") -> dict:
    return review_diff(diff_text, profile=profile)
