"""Unified diff parsing for Diff Review Forge.

Pure standard library. Understands the subset of git diff output that shows up
in pull requests, git show, review tabs and patch files:

    diff --git a/path b/path
    new file mode 100644
    index 1111111..2222222 100644
    --- a/path
    +++ b/path
    @@ -12,7 +12,9 @@ def handler():
     context
    -removed
    +added

The parser is deliberately forgiving: a patch pasted without the git header
(just ---/+++ blocks) still parses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

ENGINE_VERSION = "1.0.0"

GIT_HEADER_RE = re.compile(r"^diff --git a/(?P<old>.+?) b/(?P<new>.+)$")
HUNK_RE = re.compile(
    r"^@@ -(?P<os>\d+)(?:,(?P<oc>\d+))? \+(?P<ns>\d+)(?:,(?P<nc>\d+))? @@(?P<ctx>.*)$"
)

LANG_BY_EXT = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".rb": "ruby",
    ".rs": "rust",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".swift": "swift",
    ".scala": "scala",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ps1": "powershell",
    ".sql": "sql",
    ".html": "html",
    ".htm": "html",
    ".vue": "vue",
    ".svelte": "svelte",
    ".css": "css",
    ".scss": "css",
    ".less": "css",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".ini": "ini",
    ".cfg": "ini",
    ".md": "markdown",
    ".rst": "restructuredtext",
    ".txt": "text",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".gradle": "groovy",
    ".ipynb": "notebook",
    ".lua": "lua",
    ".r": "r",
    ".pl": "perl",
    ".dart": "dart",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".zig": "zig",
}

GENERATED_HINTS = (
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "cargo.lock",
    "composer.lock",
    "go.sum",
    "gemfile.lock",
    "pipfile.lock",
    ".min.js",
    ".min.css",
    ".bundle.js",
    ".pb.go",
    "_pb2.py",
    ".g.dart",
    "generated/",
    "__generated__/",
)

VENDOR_HINTS = (
    "node_modules/",
    "vendor/",
    "third_party/",
    "thirdparty/",
    "bower_components/",
    "site-packages/",
    ".venv/",
    "venv/",
    "dist/",
    "build/",
    ".next/",
    "coverage/",
)

TEST_DIR_HINTS = ("/test/", "/tests/", "/spec/", "/specs/", "/__tests__/", "/testing/", "/e2e/")
TEST_FILE_HINTS = ("test_", "_test.", ".test.", ".spec.", "_spec.", "conftest.py", "tests.py")

DOC_EXTS = (".md", ".rst", ".adoc", ".txt", ".markdown")
CONFIG_EXTS = (".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".lock", ".properties")
DATA_EXTS = (".sql", ".csv", ".tsv", ".graphql", ".proto")

SECRET_WORDS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "accesskey",
    "access_key",
    "private_key",
    "privatekey",
    "client_secret",
    "auth_token",
    "credential",
)

MONEY_WORDS = ("price", "amount", "total", "cost", "balance", "fee", "salary", "revenue")


@dataclass
class HunkLine:
    kind: str  # "add" | "del" | "ctx"
    text: str
    old_no: Optional[int] = None
    new_no: Optional[int] = None


@dataclass
class Hunk:
    old_start: int = 0
    old_count: int = 0
    new_start: int = 0
    new_count: int = 0
    heading: str = ""
    lines: List[HunkLine] = field(default_factory=list)

    @property
    def added(self) -> List[HunkLine]:
        return [l for l in self.lines if l.kind == "add"]

    @property
    def removed(self) -> List[HunkLine]:
        return [l for l in self.lines if l.kind == "del"]


@dataclass
class DiffFile:
    old_path: str = ""
    new_path: str = ""
    status: str = "modified"
    is_binary: bool = False
    hunks: List[Hunk] = field(default_factory=list)
    mode_note: str = ""

    @property
    def path(self) -> str:
        return self.new_path or self.old_path or "(unknown)"

    @property
    def language(self) -> str:
        name = self.path.rsplit("/", 1)[-1].lower()
        if name in ("dockerfile", "makefile"):
            return name
        ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
        return LANG_BY_EXT.get(ext, "other")

    @property
    def category(self) -> str:
        return classify_category(self.path)

    @property
    def is_test(self) -> bool:
        return self.category == "test"

    @property
    def is_generated(self) -> bool:
        return classify_generated(self.path)

    @property
    def additions(self) -> int:
        return sum(len(h.added) for h in self.hunks)

    @property
    def deletions(self) -> int:
        return sum(len(h.removed) for h in self.hunks)

    @property
    def added_lines(self) -> List[HunkLine]:
        out = []
        for h in self.hunks:
            out.extend(h.added)
        return out

    @property
    def removed_lines(self) -> List[HunkLine]:
        out = []
        for h in self.hunks:
            out.extend(h.removed)
        return out

    @property
    def view(self) -> List[HunkLine]:
        """Flat hunk-local view of the file: additions, deletions and context."""
        out = []
        for h in self.hunks:
            out.extend(h.lines)
        return out

    @property
    def estimated_length(self) -> int:
        """Rough size of the file after the change (new-file line numbers)."""
        if not self.hunks:
            return 0
        last = self.hunks[-1]
        return last.new_start + max(last.new_count, 0)


@dataclass
class DiffSet:
    files: List[DiffFile] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    raw_line_count: int = 0

    @property
    def additions(self) -> int:
        return sum(f.additions for f in self.files)

    @property
    def deletions(self) -> int:
        return sum(f.deletions for f in self.files)

    @property
    def source_files(self) -> List[DiffFile]:
        return [f for f in self.files if f.category == "source" and not f.is_generated]

    @property
    def test_files(self) -> List[DiffFile]:
        return [f for f in self.files if f.category == "test" and not f.is_generated]

    @property
    def languages(self) -> List[str]:
        return sorted({f.language for f in self.files if f.language != "other"})

    def categories(self) -> dict:
        counts = {}
        for f in self.files:
            counts[f.category] = counts.get(f.category, 0) + 1
        return counts


def classify_generated(path: str) -> bool:
    low = path.lower()
    base = low.rsplit("/", 1)[-1]
    if any(h in low for h in GENERATED_HINTS):
        return True
    if base in GENERATED_HINTS:
        return True
    return False


def classify_vendored(path: str) -> bool:
    low = path.lower()
    return any(h in low for h in VENDOR_HINTS)


def classify_category(path: str) -> str:
    low = path.lower()
    base = low.rsplit("/", 1)[-1]
    if classify_generated(path) or classify_vendored(path):
        return "generated"
    if any(seg in low for seg in TEST_DIR_HINTS):
        return "test"
    for hint in TEST_FILE_HINTS:
        if base.startswith(hint) or hint in base:
            return "test"
    if base.endswith(DOC_EXTS):
        return "docs"
    if base.endswith(CONFIG_EXTS):
        return "config"
    if base.endswith(DATA_EXTS):
        return "data"
    return "source"


def _clean_path(raw: str) -> str:
    value = raw.strip()
    if "\t" in value:
        value = value.split("\t", 1)[0]
    value = value.strip()
    if value.startswith('"') and value.endswith('"') and len(value) > 1:
        value = value[1:-1]
    if value == "/dev/null":
        return value
    for prefix in ("a/", "b/", "i/", "w/", "c/", "o/"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    return value


def _looks_like_diff(text: str) -> bool:
    if not text:
        return False
    if "@@" in text and ("--- " in text or "diff --git" in text):
        return True
    return "diff --git" in text


def _parse_hunk_body(raw: List[str], i: int, hunk: Hunk) -> int:
    old_left = hunk.old_count
    new_left = hunk.new_count
    old_no = hunk.old_start
    new_no = hunk.new_start
    n = len(raw)
    while i < n:
        if old_left <= 0 and new_left <= 0:
            break
        line = raw[i]
        if line.startswith("\\"):
            i += 1
            continue
        if line.startswith("+"):
            hunk.lines.append(HunkLine("add", line[1:], None, new_no))
            new_no += 1
            new_left -= 1
            i += 1
            continue
        if line.startswith("-"):
            hunk.lines.append(HunkLine("del", line[1:], old_no, None))
            old_no += 1
            old_left -= 1
            i += 1
            continue
        if line.startswith(" "):
            hunk.lines.append(HunkLine("ctx", line[1:], old_no, new_no))
            old_no += 1
            new_no += 1
            old_left -= 1
            new_left -= 1
            i += 1
            continue
        if line == "":
            hunk.lines.append(HunkLine("ctx", "", old_no, new_no))
            old_no += 1
            new_no += 1
            old_left -= 1
            new_left -= 1
            i += 1
            continue
        break
    return i


def parse_diff(text: str) -> DiffSet:
    """Parse unified diff text into a DiffSet."""
    result = DiffSet()
    if not text or not text.strip():
        result.warnings.append("Empty input.")
        return result

    normalised = text.replace("\r\n", "\n").replace("\r", "\n")
    raw = normalised.split("\n")
    result.raw_line_count = len(raw)

    if not _looks_like_diff(normalised):
        result.warnings.append(
            "No unified diff found. Paste the output of git diff, git show or a PR patch."
        )
        return result

    files: List[DiffFile] = []
    cur: Optional[DiffFile] = None
    i = 0
    n = len(raw)

    while i < n:
        line = raw[i]

        if line.startswith("diff --git "):
            match = GIT_HEADER_RE.match(line)
            cur = DiffFile(status="modified")
            if match:
                cur.old_path = _clean_path(match.group("old"))
                cur.new_path = _clean_path(match.group("new"))
            files.append(cur)
            i += 1
            continue

        if line.startswith("--- "):
            path = _clean_path(line[4:])
            if cur is None or cur.hunks:
                cur = DiffFile(old_path=path, new_path=path, status="modified")
                files.append(cur)
            else:
                cur.old_path = path
            i += 1
            continue

        if line.startswith("+++ "):
            path = _clean_path(line[4:])
            if cur is None:
                cur = DiffFile(old_path="", new_path=path, status="modified")
                files.append(cur)
            else:
                cur.new_path = path
            i += 1
            continue

        if cur is None:
            i += 1
            continue

        if line.startswith("new file mode"):
            cur.status = "added"
            cur.mode_note = line.strip()
        elif line.startswith("deleted file mode"):
            cur.status = "deleted"
            cur.mode_note = line.strip()
        elif line.startswith("rename from"):
            cur.old_path = _clean_path(line[len("rename from "):])
            cur.status = "renamed"
        elif line.startswith("rename to"):
            cur.new_path = _clean_path(line[len("rename to "):])
            cur.status = "renamed"
        elif line.startswith("Binary files") or line.startswith("GIT binary patch"):
            cur.is_binary = True
        elif line.startswith("@@"):
            match = HUNK_RE.match(line)
            if not match:
                i += 1
                continue
            hunk = Hunk(
                old_start=int(match.group("os")),
                old_count=int(match.group("oc") or 1),
                new_start=int(match.group("ns")),
                new_count=int(match.group("nc") or 1),
                heading=(match.group("ctx") or "").strip(),
            )
            cur.hunks.append(hunk)
            i = _parse_hunk_body(raw, i + 1, hunk)
            continue
        elif line.startswith("index ") or line.startswith("similarity index"):
            pass
        elif line.startswith("old mode") or line.startswith("new mode"):
            cur.mode_note = line.strip()

        i += 1

    for f in files:
        if f.old_path == "/dev/null":
            f.status = "added"
            f.old_path = f.new_path
        if f.new_path == "/dev/null":
            f.status = "deleted"
            f.new_path = f.old_path
        if not f.new_path and f.old_path:
            f.new_path = f.old_path
        if not f.old_path and f.new_path:
            f.old_path = f.new_path

    files = [f for f in files if f.hunks or f.is_binary]
    result.files = files
    if not files:
        result.warnings.append(
            "No file hunks could be parsed. Make sure the patch includes @@ hunk headers."
        )
    return result


def indent_of(text: str) -> int:
    return len(text) - len(text.lstrip(" \t"))


def is_blank(text: str) -> bool:
    return not text.strip()


def looks_like_code_comment(text: str) -> bool:
    stripped = text.strip()
    if not stripped.startswith(("#", "//", "*", "/*", "<!--")):
        return False
    body = stripped.lstrip("#/ *<!")
    signals = ("def ", "function ", "if ", "for ", "while ", "return ", "class ", "=>", "{", "};", ");")
    return any(sig in body for sig in signals)
