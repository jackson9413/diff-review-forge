"""SQLite run log for Diff Review Forge."""

from __future__ import annotations

import json
import os
import sqlite3
from typing import List, Optional

DB_PATH = os.environ.get(
    "DIFF_REVIEW_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "runs.db")
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    title TEXT NOT NULL,
    profile TEXT NOT NULL,
    verdict TEXT NOT NULL,
    score REAL NOT NULL,
    files INTEGER NOT NULL,
    additions INTEGER NOT NULL,
    deletions INTEGER NOT NULL,
    findings INTEGER NOT NULL,
    diff_text TEXT NOT NULL,
    summary TEXT NOT NULL,
    rating INTEGER,
    notes TEXT NOT NULL DEFAULT ''
);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(_SCHEMA)


def _row_to_dict(row: sqlite3.Row) -> dict:
    data = dict(row)
    data.pop("diff_text", None)
    return data


def save_run(
    title: str,
    profile: str,
    diff_text: str,
    result: dict,
    rating: Optional[int] = None,
    notes: str = "",
) -> int:
    init_db()
    meta = result["meta"]
    score = result["score"]
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO runs (created_at, title, profile, verdict, score, files, additions,"
            " deletions, findings, diff_text, summary, rating, notes)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                meta["reviewed_at"],
                title,
                profile,
                score["verdict"],
                score["overall"],
                meta["files"],
                meta["additions"],
                meta["deletions"],
                score["counts"]["total"],
                diff_text,
                result["summary"],
                rating,
                notes or "",
            ),
        )
        return int(cur.lastrowid)


def list_runs(limit: int = 50) -> List[dict]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, created_at, title, profile, verdict, score, files, additions, deletions,"
            " findings, summary, rating, notes FROM runs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_run(run_id: int) -> Optional[dict]:
    init_db()
    with _connect() as conn:
        row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if not row:
        return None
    return dict(row)


def update_run(
    run_id: int, rating: Optional[int] = None, notes: Optional[str] = None
) -> Optional[dict]:
    init_db()
    with _connect() as conn:
        row = conn.execute("SELECT id FROM runs WHERE id = ?", (run_id,)).fetchone()
        if not row:
            return None
        if rating is not None:
            conn.execute("UPDATE runs SET rating = ? WHERE id = ?", (rating, run_id))
        if notes is not None:
            conn.execute("UPDATE runs SET notes = ? WHERE id = ?", (notes, run_id))
    return get_run(run_id)


def delete_run(run_id: int) -> bool:
    init_db()
    with _connect() as conn:
        cur = conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))
        return cur.rowcount > 0
