"""Export helpers for Diff Review Forge (Markdown, JSON, CSV)."""

from __future__ import annotations

import csv
import io
import json


def _bar(score: float, width: int = 20) -> str:
    filled = int(round(max(0.0, min(100.0, score)) / 100.0 * width))
    return "#" * filled + "." * (width - filled)


def to_markdown(result: dict) -> str:
    score = result["score"]
    meta = result["meta"]
    lines = []
    lines.append("# Code review report")
    lines.append("")
    lines.append("**Verdict:** " + score["verdict_label"] + " - " + str(score["overall"]) + "/100")
    lines.append("")
    lines.append(
        "- Profile: " + meta["profile_label"] + " (" + meta["profile"] + ")"
    )
    lines.append(
        "- Diff: "
        + str(meta["files"])
        + " file(s), +"
        + str(meta["additions"])
        + " / -"
        + str(meta["deletions"])
    )
    if meta["languages"]:
        lines.append("- Languages: " + ", ".join(meta["languages"]))
    lines.append("- Reviewed: " + meta["reviewed_at"])
    lines.append("")
    lines.append("> " + result["summary"])
    lines.append("")

    lines.append("## Scorecard")
    lines.append("")
    lines.append("| Axis | Score | Weight | Findings | Bar |")
    lines.append("| --- | --- | --- | --- | --- |")
    for axis in score["axes"]:
        if not axis["applicable"]:
            continue
        lines.append(
            "| "
            + axis["label"]
            + " | "
            + str(axis["score"])
            + " | "
            + str(axis["weight"])
            + "% | "
            + str(axis["findings"])
            + " | "
            + _bar(axis["score"])
            + " |"
        )
    lines.append("")

    if score["caps"]:
        lines.append("### Structural caps applied")
        lines.append("")
        for cap in score["caps"]:
            lines.append("- " + cap["reason"] + " (cap: " + str(cap["limit"]) + ")")
        lines.append("")

    counts = score["counts"]
    lines.append(
        "Findings: "
        + str(counts["critical"])
        + " critical, "
        + str(counts["high"])
        + " high, "
        + str(counts["medium"])
        + " medium, "
        + str(counts["low"])
        + " low."
    )
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not result["findings"]:
        lines.append("Nothing flagged. This diff looks clean.")
        lines.append("")
    else:
        for f in result["findings"]:
            location = f["path"] + (":" + str(f["line"]) if f["line"] else "")
            lines.append(
                "### "
                + f["id"]
                + " - "
                + f["severity_label"]
                + " - "
                + f["title"]
            )
            lines.append("")
            lines.append("- Location: " + location)
            lines.append("- Axis: " + f["axis_label"] + " (rule: " + f["rule"] + ")")
            lines.append("- Evidence: " + f["evidence"])
            lines.append("- Why it matters: " + f["why"])
            lines.append("- Fix: " + f["fix"])
            if f.get("comment"):
                lines.append("- Suggested comment: " + f["comment"])
            lines.append("")

    if result.get("breaking_changes"):
        lines.append("## Breaking changes")
        lines.append("")
        for bc in result["breaking_changes"]:
            lines.append(
                "- " + bc["title"] + " (" + bc["path"] + ") - " + bc["detail"]
            )
        lines.append("")

    if result.get("coverage"):
        cov = result["coverage"]
        lines.append("## Test coverage")
        lines.append("")
        lines.append(
            "- Source files changed: "
            + str(cov["source_files"])
            + ", test files changed: "
            + str(cov["test_files"])
        )
        lines.append("- " + cov["note"])
        lines.append("")

    lines.append("## Fix plan")
    lines.append("")
    if not result.get("plan"):
        lines.append("No fixes needed.")
        lines.append("")
    else:
        lines.append("| # | Action | Axis | Count | Score after |")
        lines.append("| --- | --- | --- | --- | --- |")
        for step in result["plan"]:
            lines.append(
                "| "
                + str(step["step"])
                + " | "
                + step["title"]
                + " | "
                + step["axis_label"]
                + " | "
                + str(step["count"])
                + " | "
                + str(step["score_after"])
                + " |"
            )
        lines.append("")

    lines.append("## Files")
    lines.append("")
    lines.append("| File | Status | Language | +/- | Risk |")
    lines.append("| --- | --- | --- | --- | --- |")
    for row in result.get("files", []):
        lines.append(
            "| "
            + row["path"]
            + " | "
            + row["status"]
            + " | "
            + row["language"]
            + " | +"
            + str(row["additions"])
            + " / -"
            + str(row["deletions"])
            + " | "
            + str(row["risk"])
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def to_json(result: dict) -> str:
    return json.dumps(result, indent=2, sort_keys=False)


def to_csv(result: dict) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "id",
            "severity",
            "axis",
            "rule",
            "path",
            "line",
            "title",
            "evidence",
            "why",
            "fix",
        ]
    )
    for f in result.get("findings", []):
        writer.writerow(
            [
                f["id"],
                f["severity"],
                f["axis"],
                f["rule"],
                f["path"],
                f["line"] or "",
                f["title"],
                f["evidence"],
                f["why"],
                f["fix"],
            ]
        )
    return buf.getvalue()
