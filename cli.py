#!/usr/bin/env python3
"""Command line interface for Diff Review Forge.

    python3 cli.py review change.diff
    python3 cli.py review change.diff --profile security_audit --json
    python3 cli.py export change.diff --format md --out review.md
    python3 cli.py samples
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import engine      # noqa: E402
import exporters  # noqa: E402
from samples import get_sample, list_samples  # noqa: E402


def _load(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    if path in ("-s", "--sample"):
        raise SystemExit("use 'python3 cli.py sample-diff <id>' to print a sample diff")
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _print_text(result: dict) -> None:
    score = result["score"]
    print("Verdict : " + score["verdict_label"] + " (" + str(score["overall"]) + "/100)")
    print("Profile : " + result["meta"]["profile_label"])
    print(
        "Diff    : "
        + str(result["meta"]["files"])
        + " file(s), +"
        + str(result["meta"]["additions"])
        + " / -"
        + str(result["meta"]["deletions"])
    )
    print("")
    for axis in score["axes"]:
        if not axis["applicable"]:
            continue
        print(
            "  "
            + axis["label"].ljust(26)
            + str(axis["score"]).rjust(5)
            + "  "
            + str(axis["findings"]).rjust(2)
            + " findings"
        )
    print("")
    for f in result["findings"]:
        location = f["path"] + (":" + str(f["line"]) if f["line"] else "")
        print(
            "["
            + f["severity"].upper().ljust(8)
            + "] "
            + f["title"]
            + "  ("
            + location
            + ")"
        )
        print("           " + f["fix"])
    if result.get("plan"):
        print("")
        print("Fix plan:")
        for step in result["plan"]:
            print(
                "  "
                + str(step["step"]).rjust(2)
                + ". "
                + step["title"]
                + "  -> score "
                + str(step["score_after"])
            )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="diff-review-forge")
    sub = parser.add_subparsers(dest="command", required=True)

    review_cmd = sub.add_parser("review", help="review a unified diff file")
    review_cmd.add_argument("path", help="path to a diff file, or - for stdin")
    review_cmd.add_argument("--profile", default="general", choices=sorted(engine.PROFILES.keys()))
    review_cmd.add_argument("--json", action="store_true", help="print the full JSON result")
    review_cmd.add_argument("--out", help="write the report to this file")

    export_cmd = sub.add_parser("export", help="export a review report")
    export_cmd.add_argument("path")
    export_cmd.add_argument("--profile", default="general", choices=sorted(engine.PROFILES.keys()))
    export_cmd.add_argument("--format", default="md", choices=["md", "json", "csv"])
    export_cmd.add_argument("--out")

    sample_cmd = sub.add_parser("samples", help="list the built-in sample diffs")
    sample_cmd.add_argument("--id", help="print one sample diff")

    args = parser.parse_args(argv)

    if args.command == "samples":
        if args.id:
            sample = get_sample(args.id)
            if not sample:
                print("Unknown sample: " + args.id)
                return 1
            print(sample["diff"])
            return 0
        for s in list_samples():
            print(s["id"].ljust(24) + s["title"])
        return 0

    try:
        text = _load(args.path)
    except OSError as exc:
        print("Could not read " + args.path + ": " + str(exc))
        return 1

    result = engine.review_diff(text, profile=args.profile)

    if args.command == "review":
        if args.json:
            body = exporters.to_json(result)
        else:
            body = exporters.to_markdown(result)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write(body)
            print("Wrote " + args.out)
        elif args.json:
            print(body)
        else:
            _print_text(result)
        return 0

    if args.format == "json":
        body = exporters.to_json(result)
    elif args.format == "csv":
        body = exporters.to_csv(result)
    else:
        body = exporters.to_markdown(result)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(body)
        print("Wrote " + args.out)
    else:
        print(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
