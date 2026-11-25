"""Review rules for Diff Review Forge.

Every rule works on the ADDED lines of a diff (the change under review) plus
the hunk-local context around them. Each finding carries the evidence that
triggered it, why it matters and a concrete fix.

Five axes:
    correctness    - logic bugs that will bite at runtime
    security       - injection, credentials, unsafe defaults
    performance    - N+1 work, hot loops, waste
    testing        - missing or weakened verification
    maintainability - readability, API stability, review hygiene
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from diffparse import (
    DiffFile,
    DiffSet,
    MONEY_WORDS,
    SECRET_WORDS,
    indent_of,
    is_blank,
    looks_like_code_comment,
)

AXES = ("correctness", "security", "performance", "testing", "maintainability")

AXIS_LABELS = {
    "correctness": "Correctness & logic",
    "security": "Security",
    "performance": "Performance",
    "testing": "Testing & verification",
    "maintainability": "Maintainability",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_PENALTY = {"critical": 45, "high": 18, "medium": 7, "low": 2}
SEVERITY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


@dataclass
class Finding:
    rule: str
    axis: str
    severity: str
    title: str
    path: str
    line: Optional[int]
    evidence: str
    why: str
    fix: str
    comment: str = ""

    def to_dict(self, index: int) -> dict:
        return {
            "id": "F%d" % index,
            "rule": self.rule,
            "axis": self.axis,
            "axis_label": AXIS_LABELS.get(self.axis, self.axis),
            "severity": self.severity,
            "severity_label": SEVERITY_LABEL.get(self.severity, self.severity),
            "title": self.title,
            "path": self.path,
            "line": self.line,
            "evidence": self.evidence,
            "why": self.why,
            "fix": self.fix,
            "comment": self.comment,
        }


def _trim(text: str, limit: int = 220) -> str:
    text = text.rstrip()
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def _finding(rule: dict, path: str, line: Optional[int], evidence: str) -> Finding:
    return Finding(
        rule=rule["id"],
        axis=rule["axis"],
        severity=rule["severity"],
        title=rule["title"],
        path=path,
        line=line,
        evidence=_trim(evidence),
        why=rule["why"],
        fix=rule["fix"],
        comment=rule.get("comment", ""),
    )


# --------------------------------------------------------------------------
# Line level rules
# --------------------------------------------------------------------------

LINE_RULES: List[dict] = [
    # ---------------- security ----------------
    {
        "id": "hardcoded_secret",
        "axis": "security",
        "severity": "critical",
        "title": "Hard-coded credential in the diff",
        "pattern": (
            r"(?i)(?<![A-Za-z0-9])(api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|"
            r"access[_-]?key|secret|password|passwd|pwd|auth[_-]?token|api[_-]?token|token|"
            r"private[_-]?key|credential|passphrase)(?![A-Za-z0-9])"
            r"\s*[:=]\s*[\"'][^\"'\n]{6,}[\"']"
        ),
        "exclude": (
            r"(?i)(os\.environ|getenv|process\.env|dotenv|environ\[|vault|keyring|secretmanager|"
            r"your[_-]|example|changeme|placeholder|redacted|dummy|fake|sample|xxxx|\.\.\.|"
            r"<[a-z_ -]+>|todo|fixme|config\(|settings\.|params\[|args\[|kwargs\[|os\.get\(|"
            r"\{\}|\[\]|getenv)"
        ),
        "why": (
            "A credential in source is in the git history forever, in every clone and in every "
            "CI log. Rotating it later is always harder than never committing it."
        ),
        "fix": (
            "Read it from the environment or a secret manager (os.environ, process.env, Vault, "
            "AWS Secrets Manager) and fail loudly when it is missing instead of shipping a default."
        ),
        "comment": "Please pull this credential out of the source and load it from the environment.",
    },
    {
        "id": "provider_token",
        "axis": "security",
        "severity": "critical",
        "title": "Live-looking provider token committed",
        "pattern": (
            r"\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|sk-[A-Za-z0-9_\-]{20,}|"
            r"gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9\-]{10,}|"
            r"AIza[0-9A-Za-z_\-]{30,}|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,})"
        ),
        "why": "This looks like a real, usable credential for a hosted service.",
        "fix": "Revoke the token immediately, then load the replacement from the environment.",
        "comment": "This token has to be revoked - please rotate it and use an env var.",
    },
    {
        "id": "private_key_material",
        "axis": "security",
        "severity": "critical",
        "title": "Private key material in the diff",
        "pattern": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        "why": "A committed private key means whoever clones the repo owns the identity behind it.",
        "fix": "Revoke the key, remove it from the file and store the new key in a secrets manager.",
    },
    {
        "id": "sql_injection_risk",
        "axis": "security",
        "severity": "critical",
        "title": "SQL built by string interpolation",
        "pattern": (
            r"(?i)\b(select\b[^\n]{0,120}?\bfrom\b|insert\s+into\b|update\s+[a-z_]+\s+set\b|"
            r"delete\s+from\b)[^\n]{0,140}?(\+\s*[a-z_]|\+\s*\(|%s\b|%s\)|\.format\(|f[\"'])"
        ),
        "why": (
            "Concatenating user input into SQL is the classic injection path. One quote in a "
            "search box and the whole database is exposed."
        ),
        "fix": "Use parameterised queries (cursor.execute(sql, params) or SQLAlchemy bound parameters).",
        "comment": "Please bind these values as query parameters instead of building the SQL by hand.",
    },
    {
        "id": "command_injection",
        "axis": "security",
        "severity": "critical",
        "title": "Shell command built from untrusted input",
        "pattern": (
            r"(os\.system\s*\(|subprocess\.[A-Za-z_]+\s*\([^\n]{0,120}shell\s*=\s*True|"
            r"child_process\.exec\s*\(|os\.popen\s*\()"
        ),
        "why": (
            "A shell interprets every metacharacter in the string. If any part of it comes from a "
            "request, a filename or a user, this is remote code execution."
        ),
        "fix": (
            "Call the program directly with an argument list (subprocess.run([...], shell=False)) "
            "and pass user data as separate arguments."
        ),
    },
    {
        "id": "eval_exec",
        "axis": "security",
        "severity": "critical",
        "title": "eval/exec on runtime data",
        "pattern": r"(?<![\w.])(eval|exec)\s*\(",
        "exclude": r"(?i)(exec_command|exec_sql|execve|evaluate|evaluator|executor|eval_[a-z])",
        "why": "eval turns any reachable string into code in the current process.",
        "fix": "Use ast.literal_eval for data, a dispatch table for behaviour, or an explicit parser.",
    },
    {
        "id": "unsafe_deserialization",
        "axis": "security",
        "severity": "high",
        "title": "Unsafe deserialization",
        "pattern": r"(pickle\.(load|loads)\s*\(|marshal\.loads\s*\(|yaml\.load\s*\()",
        "exclude": r"(?i)(SafeLoader|CSafeLoader)",
        "why": (
            "Unpickling or unsafe YAML loading executes code embedded in the payload. Only load "
            "data you produced yourself."
        ),
        "fix": "Use json, or yaml.safe_load / yaml.load(..., Loader=yaml.SafeLoader).",
    },
    {
        "id": "tls_verification_disabled",
        "axis": "security",
        "severity": "critical",
        "title": "TLS certificate verification disabled",
        "pattern": r"(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)",
        "why": (
            "Disabling verification removes the only protection against a man in the middle. The "
            "connection becomes encrypted but unauthenticated."
        ),
        "fix": "Leave verification on. For a self-signed cert, trust that CA explicitly (verify=/path/ca.pem).",
    },
    {
        "id": "permissive_permissions",
        "axis": "security",
        "severity": "high",
        "title": "World-writable file permissions",
        "pattern": r"(0o?777|chmod\s*\(\s*[^\n]{0,40}0o?7[0-7][0-7]|0777)",
        "why": "777 means any local user can read and rewrite the file.",
        "fix": "Grant the narrowest mode that works, usually 0o600 for secrets and 0o644 for data.",
    },
    {
        "id": "cors_wildcard",
        "axis": "security",
        "severity": "high",
        "title": "CORS allows every origin",
        "pattern": (
            r"(?i)(Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*|origins\s*=\s*[\"']\*|"
            r"CORS\([^\n]{0,80}[\"']\*)"
        ),
        "why": "Allowing every origin lets any site call this API with the visitor's cookies.",
        "fix": "List the origins that actually need access, or read them from configuration.",
    },
    {
        "id": "xss_inner_html",
        "axis": "security",
        "severity": "high",
        "title": "Unescaped HTML assigned to the DOM",
        "pattern": r"(\.innerHTML\s*=|dangerouslySetInnerHTML|v-html\s*=|document\.write\s*\()",
        "why": (
            "Anything interpolated into inner HTML is parsed as markup, so a value containing a "
            "script tag runs in the page."
        ),
        "fix": "Use textContent, or escape the value, or use a templating layer that escapes by default.",
    },
    {
        "id": "debug_enabled",
        "axis": "security",
        "severity": "medium",
        "title": "Debug mode switched on",
        "pattern": r"(?i)(\bdebug\s*=\s*True\b|FLASK_DEBUG\s*=\s*1|app\.run\([^\n]{0,80}debug\s*=\s*True)",
        "why": "Debug mode exposes stack traces, sometimes with source and environment values.",
        "fix": "Read it from configuration and keep it off outside development.",
    },
    {
        "id": "insecure_temp_file",
        "axis": "security",
        "severity": "medium",
        "title": "Predictable temporary file name",
        "pattern": r"tempfile\.mktemp\s*\(",
        "why": "mktemp only builds a name; another process can create it first and you write into their file.",
        "fix": "Use tempfile.NamedTemporaryFile or mkstemp, which create the file atomically.",
    },
    # ---------------- correctness ----------------
    {
        "id": "bare_except",
        "axis": "correctness",
        "severity": "high",
        "title": "Bare except swallows everything",
        "pattern": r"^\s*except\s*:",
        "why": (
            "A bare except also catches KeyboardInterrupt and SystemExit, so the program becomes "
            "impossible to stop and real errors are hidden."
        ),
        "fix": "Catch the exception type you expect (except ValueError:) and let the rest propagate.",
    },
    {
        "id": "mutable_default_argument",
        "axis": "correctness",
        "severity": "high",
        "title": "Mutable default argument",
        "pattern": r"def\s+\w+\s*\([^\n)]*=\s*(\[\]|\{\}|set\(\)|list\(\)|dict\(\))",
        "why": (
            "The default is created once when the function is defined, so every call shares it and "
            "state leaks between callers."
        ),
        "fix": "Use None as the default and build the container inside the function.",
    },
    {
        "id": "none_comparison",
        "axis": "correctness",
        "severity": "medium",
        "title": "Comparison with None using ==",
        "pattern": r"[!=]=\s*None\b",
        "why": "is None is the correct identity check; == None also matches objects that pretend to be None.",
        "fix": "Use 'is None' and 'is not None'.",
    },
    {
        "id": "type_equality_check",
        "axis": "correctness",
        "severity": "medium",
        "title": "Type checked with ==",
        "pattern": r"\btype\s*\([^\n)]*\)\s*[=!]=\s",
        "why": "Type checks break for subclasses and for proxy objects that behave like the type.",
        "fix": "Use isinstance(x, Type).",
    },
    {
        "id": "identity_comparison_literal",
        "axis": "correctness",
        "severity": "medium",
        "title": "Identity check against a literal",
        "pattern": r"\bis\s+(-?\d+|\"[^\"]*\"|'[^']*'|\[[^\]]*\]|\{[^\}]*\})",
        "why": "is compares object identity. Two equal strings can be different objects, so the check can fail.",
        "fix": "Use == for value comparisons.",
    },
    {
        "id": "assert_in_production_code",
        "axis": "correctness",
        "severity": "medium",
        "title": "assert used for validation in shipped code",
        "pattern": r"^\s*assert\s+",
        "cats": ("source",),
        "why": "python runs with -O strips every assert, so the check silently disappears in production.",
        "fix": "Raise an explicit exception instead of asserting.",
    },
    {
        "id": "off_by_one_length",
        "axis": "correctness",
        "severity": "medium",
        "title": "Possible off-by-one on a length comparison",
        "pattern": r"<=\s*len\s*\(",
        "langs": ("python",),
        "why": "A valid index is at most len(x) - 1, so <= len(x) can reach past the end.",
        "fix": "Compare with < len(x), or iterate over the sequence.",
    },
    {
        "id": "naive_datetime",
        "axis": "correctness",
        "severity": "medium",
        "title": "Naive datetime",
        "pattern": r"\bdatetime\.(now|utcnow)\s*\(",
        "langs": ("python",),
        "why": (
            "now() and utcnow() return a datetime with no timezone. Comparing it with an aware "
            "datetime raises, and storing it loses the offset."
        ),
        "fix": "Use datetime.now(timezone.utc) or zoneinfo, and keep everything timezone-aware.",
    },
    {
        "id": "loose_equality_js",
        "axis": "correctness",
        "severity": "medium",
        "title": "Loose equality in JavaScript",
        "pattern": r"(?<![=!<>])(?<![=!<>])==(?!=)|!=(?!=)",
        "langs": ("javascript", "typescript"),
        "exclude": r"(?i)(===|!==|!==|//|\*|/\*)",
        "why": (
            "== coerces types, so '0' == false is true and null == undefined is true. These "
            "comparisons are a classic source of hard to find bugs."
        ),
        "fix": "Use === and !== so the comparison does not change type.",
    },
    {
        "id": "sql_select_star",
        "axis": "performance",
        "severity": "low",
        "title": "SELECT * in application code",
        "pattern": r"(?i)select\s+\*",
        "why": (
            "Every column is fetched and shipped over the wire even when the code uses two of "
            "them, and the query breaks when someone adds a column."
        ),
        "fix": "List the columns the code actually uses.",
    },
    {
        "id": "magic_time_constant",
        "axis": "maintainability",
        "severity": "low",
        "title": "Magic time constant",
        "pattern": r"(==|>=|<=|>|<)\s*(86400|604800|3600|900|31536000)\b",
        "why": "The number is meaningless without context and easy to get wrong.",
        "fix": "Name it: DAY_SECONDS = 86400, or use timedelta(days=1).",
    },
    # ---------------- testing ----------------
    {
        "id": "test_skipped",
        "axis": "testing",
        "severity": "medium",
        "title": "Test skipped or marked expected-failure",
        "pattern": (
            r"(@pytest\.mark\.(skip|skipif|xfail)|@unittest\.skip|@Ignore\b|"
            r"\bxit\s*\(|\bxdescribe\s*\(|\btest\.skip\s*\(|\bdescribe\.skip\s*\(|\bt\.Skip\s*\()"
        ),
        "cats": ("test",),
        "why": (
            "A skipped test gives the appearance of coverage while checking nothing, and it keeps "
            "skipping long after the reason stopped being true."
        ),
        "fix": "Fix the test, or delete it and open an issue that says why it cannot run.",
    },
    {
        "id": "weak_assertion",
        "axis": "testing",
        "severity": "low",
        "title": "Weak assertion",
        "pattern": r"(assertTrue\s*\(\s*[^,)]*\)|assert\.ok\s*\(|toBeTruthy\s*\(\s*\)|toBeDefined\s*\(\s*\))",
        "cats": ("test",),
        "why": "A truthiness check passes for almost anything, including the wrong value.",
        "fix": "Assert the exact expected value: assertEqual(result.status, 200).",
    },
    {
        "id": "time_dependent_test",
        "axis": "testing",
        "severity": "medium",
        "title": "Test depends on the current time",
        "pattern": r"\b(datetime\.(now|utcnow)\s*\(|Date\.now\s*\(|time\.time\s*\(|new Date\s*\(\s*\))",
        "cats": ("test",),
        "why": (
            "The test passes today and fails at midnight, at month end or in a different timezone. "
            "Flaky tests are worse than missing tests because people learn to ignore them."
        ),
        "fix": "Freeze the clock or inject the time as a parameter.",
    },
    {
        "id": "sleep_in_request_path",
        "axis": "performance",
        "severity": "medium",
        "title": "Sleep in a request path",
        "pattern": r"\btime\.sleep\s*\(",
        "cats": ("source",),
        "why": (
            "Sleeping inside a request blocks a worker thread for no reason. Under load the "
            "requests queue up behind each other and the service falls over."
        ),
        "fix": "Remove the sleep. If you are waiting for something, await it instead of guessing a duration.",
        "comment": "This sleep blocks the request - can we wait for the real signal instead?",
    },
    {
        "id": "sleep_in_test",
        "axis": "testing",
        "severity": "medium",
        "title": "Sleep used to wait in a test",
        "pattern": r"\btime\.sleep\s*\(",
        "cats": ("test",),
        "why": "Sleeping is both slow and unreliable: on a loaded machine the wait is too short.",
        "fix": "Poll for the condition with a timeout, or wait on an explicit signal.",
    },
    # ---------------- maintainability ----------------
    {
        "id": "todo_marker_left",
        "axis": "maintainability",
        "severity": "medium",
        "title": "TODO / FIXME marker left in the change",
        "pattern": r"(?i)\b(TODO|FIXME|XXX|HACK|REVIEW ME)\b",
        "why": "Markers without an owner and a ticket are the same as nothing, but they read as if somebody is on it.",
        "fix": "Resolve it, or turn it into a tracked issue with an owner and a ticket id.",
    },
    {
        "id": "commented_out_code",
        "axis": "maintainability",
        "severity": "medium",
        "title": "Commented-out code",
        "pattern": r"^\s*(#|//)\s*(def |class |function |if |for |while |return |import |const |let |var )",
        "why": (
            "Dead code in comments rots silently: it no longer compiles, nobody notices, and the next "
            "person copies it."
        ),
        "fix": "Delete it. Version control keeps the history if it is ever needed.",
    },
    {
        "id": "debug_print_left",
        "axis": "maintainability",
        "severity": "low",
        "title": "Debug print left in the code",
        "pattern": r"(^\s*print\s*\(|console\.log\s*\(|System\.out\.print(ln)?\s*\(|fmt\.Println\s*\()",
        "cats": ("source",),
        "why": "Stray prints leak data into logs and make real output hard to find.",
        "fix": "Use the logging framework with a level, and remove the print.",
    },
    {
        "id": "debugger_statement",
        "axis": "maintainability",
        "severity": "medium",
        "title": "Debugger breakpoint left in the code",
        "pattern": r"(^\s*debugger\s*;|\bpdb\.set_trace\s*\(|\bconsole\.debug\s*\(\s*[\"'])",
        "why": "A leftover breakpoint stops the program in production and stalls the request.",
        "fix": "Delete it before merging.",
    },
    {
        "id": "wildcard_import",
        "axis": "maintainability",
        "severity": "medium",
        "title": "Wildcard import",
        "pattern": r"^\s*from\s+[\w.]+\s+import\s+\*",
        "why": "You cannot tell where a name came from, and a new import in the module can shadow it.",
        "fix": "Import the names you actually use.",
    },
    {
        "id": "global_statement",
        "axis": "maintainability",
        "severity": "medium",
        "title": "global statement in a function",
        "pattern": r"^\s*global\s+\w+",
        "why": "Mutable module state makes the function impossible to test in isolation and hides data flow.",
        "fix": "Return the value and let the caller decide, or pass the state in as an argument.",
    },
    {
        "id": "long_line",
        "axis": "maintainability",
        "severity": "low",
        "title": "Very long line",
        "pattern": r"^.{121,}$",
        "why": "Long lines hide the structure of the expression and make diffs unreadable.",
        "fix": "Split the expression over several lines.",
    },
    {
        "id": "deep_nesting",
        "axis": "maintainability",
        "severity": "medium",
        "title": "Deeply nested block",
        "pattern": r"^\s{17,}\S",
        "why": "Four or more levels of nesting usually means a branch needs to be extracted into its own function.",
        "fix": "Extract the inner block into a named function or use an early return.",
    },
]


# --------------------------------------------------------------------------
# Helpers for block level rules
# --------------------------------------------------------------------------


def _body_after(view, idx: int, max_lines: int = 30) -> List:
    """Lines that belong to the block opened at view[idx] (deeper indent)."""
    if idx >= len(view):
        return []
    base = indent_of(view[idx].text)
    out = []
    for j in range(idx + 1, min(len(view), idx + max_lines + 1)):
        line = view[j]
        if is_blank(line.text):
            continue
        if indent_of(line.text) <= base:
            break
        out.append(line)
    return out


def _is_loop(line_text: str) -> bool:
    stripped = line_text.strip()
    return bool(
        re.match(r"(for\s|while\s|forEach\s*\(|\.map\s*\(|\.forEach\s*\(|for\s+\w+\s*<-)", stripped)
    ) and not stripped.startswith("#") and not stripped.startswith("//")


LOOP_RE = re.compile(r"^\s*(for\b|while\b|forEach\s*\(|\.map\s*\(|\.forEach\s*\()")
DB_CALL_RE = re.compile(
    r"(\.execute\s*\(|\.executemany\s*\(|\.fetchall\s*\(|\.fetchone\s*\(|session\.query\s*\(|"
    r"\.filter\s*\(|\.exclude\s*\(|\.values_list\s*\(|\.get\s*\(\s*request|"
    r"\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE FROM\b|\bfind\s*\(\s*\{|\.findOne\s*\()"
)
HTTP_CALL_RE = re.compile(r"(requests\.(get|post|put|delete|patch)\s*\(|httpx\.|urllib\.request|fetch\s*\(|axios\.|http\.Get\s*\(|http\.Post\s*\()")
RECOMPILE_RE = re.compile(r"re\.(compile|findall|search|match)\s*\(|new RegExp\s*\(")
OPEN_RE = re.compile(r"(\bopen\s*\(|fs\.(readFile|readFileSync)\s*\(|File\.ReadAllText\s*\()")
APPEND_IN_LOOP_RE = re.compile(r"(\+=\s*[\"']|\+=\s*[A-Za-z_]\w*\s*\+\s*[\"']|\.append\s*\(\s*[\"']|\.push\s*\(\s*[\"'])")
MEMBERSHIP_RE = re.compile(r"\bin\s+[A-Za-z_][\w\.]*\s*(:|\)|$)")


# --------------------------------------------------------------------------
# Block level rules
# --------------------------------------------------------------------------


def rule_except_swallow(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    view = file.view
    for idx, line in enumerate(view):
        if line.kind != "add":
            continue
        if not re.match(r"^\s*except\b", line.text):
            continue
        body = _body_after(view, idx, 8)
        if not body:
            continue
        text = " ".join(b.text for b in body)
        if body[0].text.strip() == "pass":
            out.append(
                Finding(
                    rule="except_swallow",
                    axis="correctness",
                    severity="high",
                    title="Exception swallowed with pass",
                    path=file.path,
                    line=line.new_no,
                    evidence=line.text,
                    why=(
                        "The failure is caught and then ignored, so the caller believes the work "
                        "succeeded. The error surfaces later as missing data or a wrong total."
                    ),
                    fix=(
                        "Log the exception with its context and either handle it or re-raise it "
                        "(raise ... from exc)."
                    ),
                    comment="Can we log or re-raise here instead of silently passing?",
                )
            )
        elif not any(
            kw in text
            for kw in ("raise", "logger", "logging", "print", "warn", "error(", "except", "return", "abort")
        ):
            out.append(
                Finding(
                    rule="except_without_log",
                    axis="correctness",
                    severity="medium",
                    title="Exception caught with no trace left behind",
                    path=file.path,
                    line=line.new_no,
                    evidence=line.text,
                    why="The error disappears with no log line, so nobody can diagnose what went wrong.",
                    fix="Log the exception (logger.exception) and decide explicitly whether to re-raise.",
                    comment="Could we log this exception before continuing?",
                )
            )
    return out


def rule_return_in_finally(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    view = file.view
    for idx, line in enumerate(view):
        if line.kind != "add":
            continue
        if not re.match(r"^\s*finally\s*:", line.text):
            continue
        body = _body_after(view, idx, 8)
        for b in body:
            if re.match(r"^\s*return\b", b.text):
                out.append(
                    Finding(
                        rule="return_in_finally",
                        axis="correctness",
                        severity="high",
                        title="return inside finally",
                        path=file.path,
                        line=b.new_no,
                        evidence=b.text,
                        why=(
                            "A return in finally swallows any exception that is still in flight, "
                            "including the one the caller needed to see."
                        ),
                        fix="Move the return out of finally and let the finally block only clean up.",
                        comment="A return here will swallow in-flight exceptions - can we restructure?",
                    )
                )
                break
    return out


def rule_infinite_loop(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    view = file.view
    for idx, line in enumerate(view):
        if line.kind != "add":
            continue
        if not re.match(r"^\s*while\s+True\s*:", line.text):
            continue
        body = _body_after(view, idx, 25)
        if not any(re.match(r"^\s*break\b", b.text) for b in body):
            out.append(
                Finding(
                    rule="infinite_loop_risk",
                    axis="correctness",
                    severity="medium",
                    title="while True with no break in sight",
                    path=file.path,
                    line=line.new_no,
                    evidence=line.text,
                    why="Nothing in the visible block exits the loop, so it will spin forever and pin a core.",
                    fix="Add an explicit exit condition, or use a for loop over a finite sequence.",
                    comment="I cannot see a break in this loop - is there one further down?",
                )
            )
    return out


def rule_n_plus_one(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    view = file.view
    for idx, line in enumerate(view):
        if line.kind != "add":
            continue
        if not LOOP_RE.match(line.text):
            continue
        body = _body_after(view, idx, 10)
        for b in body:
            if DB_CALL_RE.search(b.text):
                out.append(
                    Finding(
                        rule="n_plus_one_query",
                        axis="performance",
                        severity="high",
                        title="Database call inside a loop",
                        path=file.path,
                        line=b.new_no,
                        evidence=b.text,
                        why=(
                            "One query per iteration turns N rows into N round trips. On a few "
                            "hundred rows that is the difference between milliseconds and minutes."
                        ),
                        fix=(
                            "Fetch the related rows in a single query (join, or an IN clause with the "
                            "collected ids) and index the loop in memory."
                        ),
                        comment="Can we fetch these in one query instead of one per row?",
                    )
                )
                break
    return out


def rule_http_in_loop(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    view = file.view
    for idx, line in enumerate(view):
        if line.kind != "add":
            continue
        if not LOOP_RE.match(line.text):
            continue
        body = _body_after(view, idx, 10)
        for b in body:
            if HTTP_CALL_RE.search(b.text):
                out.append(
                    Finding(
                        rule="http_call_in_loop",
                        axis="performance",
                        severity="medium",
                        title="HTTP request inside a loop",
                        path=file.path,
                        line=b.new_no,
                        evidence=b.text,
                        why=(
                            "Each iteration pays the full network latency. Ten items is a second of "
                            "waiting, a thousand items is a timeout."
                        ),
                        fix="Batch the requests, or run them concurrently with a bounded pool.",
                        comment="Sequential requests in a loop - worth batching or parallelising?",
                    )
                )
                break
    return out


def rule_membership_in_loop(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    view = file.view
    for idx, line in enumerate(view):
        if line.kind != "add":
            continue
        if not LOOP_RE.match(line.text):
            continue
        body = _body_after(view, idx, 10)
        for b in body:
            if MEMBERSHIP_RE.search(b.text) and "range(" not in b.text:
                out.append(
                    Finding(
                        rule="list_membership_in_loop",
                        axis="performance",
                        severity="medium",
                        title="Membership test on a list inside a loop",
                        path=file.path,
                        line=b.new_no,
                        evidence=b.text,
                        why=(
                            "The in operator scans the whole list each time, so the loop is "
                            "quadratic in the size of that list."
                        ),
                        fix="Build a set once before the loop and test membership against the set.",
                        comment="A set lookup here would turn this quadratic loop into a linear one.",
                    )
                )
                break
    return out


def rule_string_concat_in_loop(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    view = file.view
    for idx, line in enumerate(view):
        if line.kind != "add":
            continue
        if not LOOP_RE.match(line.text):
            continue
        body = _body_after(view, idx, 10)
        for b in body:
            if APPEND_IN_LOOP_RE.search(b.text):
                out.append(
                    Finding(
                        rule="string_concat_in_loop",
                        axis="performance",
                        severity="medium",
                        title="String or list grown inside a loop",
                        path=file.path,
                        line=b.new_no,
                        evidence=b.text,
                        why=(
                            "Repeated concatenation copies the whole value on every iteration, so "
                            "building a long string this way is quadratic."
                        ),
                        fix="Collect the pieces in a list and join them once after the loop.",
                        comment="Can we collect these and join once after the loop?",
                    )
                )
                break
    return out


def rule_regex_in_loop(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    view = file.view
    for idx, line in enumerate(view):
        if line.kind != "add":
            continue
        if not LOOP_RE.match(line.text):
            continue
        body = _body_after(view, idx, 10)
        for b in body:
            if RECOMPILE_RE.search(b.text):
                out.append(
                    Finding(
                        rule="regex_compiled_in_loop",
                        axis="performance",
                        severity="low",
                        title="Regular expression compiled inside a loop",
                        path=file.path,
                        line=b.new_no,
                        evidence=b.text,
                        why="The pattern is recompiled on every iteration instead of being reused.",
                        fix="Move the compile call above the loop.",
                    )
                )
                break
    return out


def rule_file_open_in_loop(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    view = file.view
    for idx, line in enumerate(view):
        if line.kind != "add":
            continue
        if not LOOP_RE.match(line.text):
            continue
        body = _body_after(view, idx, 10)
        for b in body:
            if OPEN_RE.search(b.text):
                out.append(
                    Finding(
                        rule="file_open_in_loop",
                        axis="performance",
                        severity="medium",
                        title="File opened inside a loop",
                        path=file.path,
                        line=b.new_no,
                        evidence=b.text,
                        why=(
                            "Opening the same file repeatedly wastes a syscall per iteration and "
                            "leaks file handles if an exception happens mid-loop."
                        ),
                        fix="Open the file once outside the loop and read it with a context manager.",
                    )
                )
                break
    return out


def rule_sort_in_loop(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    view = file.view
    for idx, line in enumerate(view):
        if line.kind != "add":
            continue
        if not LOOP_RE.match(line.text):
            continue
        body = _body_after(view, idx, 10)
        for b in body:
            if re.search(r"\.sort\s*\(|sorted\s*\(", b.text):
                out.append(
                    Finding(
                        rule="sort_in_loop",
                        axis="performance",
                        severity="low",
                        title="Sorting inside a loop",
                        path=file.path,
                        line=b.new_no,
                        evidence=b.text,
                        why="The same collection is re-sorted on every iteration.",
                        fix="Sort once, before the loop.",
                    )
                )
                break
    return out


def rule_long_function(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    view = file.view
    for idx, line in enumerate(view):
        if line.kind != "add":
            continue
        m = re.match(r"^\s*(def |function |func |public |private |protected )", line.text)
        if not m:
            continue
        body = _body_after(view, idx, 120)
        added_in_body = sum(1 for b in body if b.kind == "add")
        if len(body) >= 40 or added_in_body >= 35:
            out.append(
                Finding(
                    rule="long_function",
                    axis="maintainability",
                    severity="medium",
                    title="Long function",
                    path=file.path,
                    line=line.new_no,
                    evidence=line.text,
                    why=(
                        "A function this size has several reasons to change, which is exactly the "
                        "shape of code that breaks when someone changes one of them."
                    ),
                    fix="Split it into smaller functions with single responsibilities.",
                    comment="This function is getting long - worth splitting into named steps?",
                )
            )
    return out


def rule_empty_test(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    view = file.view
    for idx, line in enumerate(view):
        if line.kind != "add":
            continue
        if not re.match(r"^\s*(def test_\w+|func Test\w+|it\s*\(|test\s*\()", line.text):
            continue
        body = _body_after(view, idx, 30)
        if not body:
            continue
        text = " ".join(b.text for b in body)
        if not re.search(r"(assert|expect\s*\(|require\s*\(|should\b|assertThat|assert_)", text):
            out.append(
                Finding(
                    rule="empty_test",
                    axis="testing",
                    severity="medium",
                    title="Test with no assertion",
                    path=file.path,
                    line=line.new_no,
                    evidence=line.text,
                    why=(
                        "A test that never asserts anything passes even when the code is broken, "
                        "so it protects nothing while taking CI time."
                    ),
                    fix="Assert the observable result, or delete the test.",
                    comment="This test does not assert anything - what is it checking?",
                )
            )
    return out


def rule_closure_in_loop(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    view = file.view
    for idx, line in enumerate(view):
        if line.kind != "add":
            continue
        if not LOOP_RE.match(line.text):
            continue
        body = _body_after(view, idx, 12)
        for b in body:
            if re.match(r"^\s*(def |lambda|go func|func\s*\()", b.text) and "def " not in line.text:
                out.append(
                    Finding(
                        rule="closure_in_loop",
                        axis="correctness",
                        severity="medium",
                        title="Closure or goroutine created inside a loop",
                        path=file.path,
                        line=b.new_no,
                        evidence=b.text,
                        why=(
                            "The captured variable is shared by every iteration, so all the "
                            "callbacks see the final value instead of the value of their own round."
                        ),
                        fix="Pass the value in as a parameter, or bind it as a default argument.",
                        comment="Classic late-binding closure - can we bind the value here?",
                    )
                )
                break
    return out


def rule_promise_without_catch(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    view = file.view
    for idx, line in enumerate(view):
        if line.kind != "add":
            continue
        if ".then(" not in line.text or ".catch(" in line.text:
            continue
        if "await " in line.text:
            continue
        out.append(
            Finding(
                rule="unhandled_promise",
                axis="correctness",
                severity="low",
                title="Promise chain with no error handling",
                path=file.path,
                line=line.new_no,
                evidence=line.text,
                why=(
                    "If the promise rejects, nothing handles it: the error becomes an unhandled "
                    "rejection and the caller never learns it failed."
                ),
                fix="Add a catch handler, or use await inside a try/catch.",
            )
        )
    return out


def rule_unreachable_else(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    view = file.view
    for idx, line in enumerate(view):
        if line.kind != "add":
            continue
        if not re.match(r"^\s*else\s*:", line.text):
            continue
        # find the block before the else
        prev = None
        for j in range(idx - 1, max(-1, idx - 12), -1):
            if is_blank(view[j].text):
                continue
            prev = view[j]
            break
        if prev is None:
            continue
        body = _body_after(view, j, 12)
        if any(re.match(r"^\s*(return|raise|continue|break)\b", b.text) for b in body):
            out.append(
                Finding(
                    rule="unreachable_else",
                    axis="maintainability",
                    severity="low",
                    title="else branch after a branch that exits",
                    path=file.path,
                    line=line.new_no,
                    evidence=line.text,
                    why="The else is unreachable noise that makes the flow harder to follow.",
                    fix="Remove the else and dedent the block.",
                )
            )
    return out


def rule_weak_hash(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    for line in file.added_lines:
        text = line.text
        if not re.search(r"hashlib\.(md5|sha1)\s*\(", text):
            continue
        low = text.lower()
        if any(word in low for word in ("password", "passwd", "pwd", "secret", "token")):
            out.append(
                Finding(
                    rule="weak_hash_for_password",
                    axis="security",
                    severity="high",
                    title="Fast hash used for a password",
                    path=file.path,
                    line=line.new_no,
                    evidence=text,
                    why=(
                        "MD5 and SHA-1 are designed to be fast, which is exactly what you do not "
                        "want for a password: a GPU tries billions of them per second."
                    ),
                    fix="Use argon2, scrypt or bcrypt (passlib, argon2-cffi) with a per-user salt.",
                )
            )
    return out


def rule_insecure_random(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    for line in file.added_lines:
        text = line.text
        if not re.search(r"\brandom\.(random|randint|choice|randrange|uniform)\s*\(", text):
            continue
        low = text.lower()
        if any(word in low for word in ("token", "secret", "password", "nonce", "otp", "salt", "key")):
            out.append(
                Finding(
                    rule="insecure_random",
                    axis="security",
                    severity="medium",
                    title="Predictable randomness used for a secret",
                    path=file.path,
                    line=line.new_no,
                    evidence=text,
                    why=(
                        "random is a deterministic generator. Given the seed an attacker can "
                        "reproduce every value the application will ever produce."
                    ),
                    fix="Use the secrets module (secrets.token_hex, secrets.token_urlsafe) or os.urandom.",
                )
            )
    return out


def rule_float_money(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    for line in file.added_lines:
        text = line.text
        if not re.search(r"\bfloat\s*\(", text):
            continue
        low = text.lower()
        if any(word in low for word in MONEY_WORDS):
            out.append(
                Finding(
                    rule="float_for_money",
                    axis="correctness",
                    severity="medium",
                    title="Float used for a monetary value",
                    path=file.path,
                    line=line.new_no,
                    evidence=text,
                    why=(
                        "Binary floats cannot represent 0.10 exactly, so rounding errors accumulate "
                        "and totals stop adding up."
                    ),
                    fix="Use decimal.Decimal (or store integer minor units such as cents).",
                )
            )
    return out


def rule_removed_assertion(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    if file.category != "test":
        return out
    for line in file.removed_lines:
        if re.match(r"^\s*(assert\b|expect\s*\(|self\.assert|assertThat\s*\(|assert\s*\.)", line.text):
            out.append(
                Finding(
                    rule="test_assertion_removed",
                    axis="testing",
                    severity="high",
                    title="Assertion removed from a test",
                    path=file.path,
                    line=line.old_no,
                    evidence=line.text,
                    why=(
                        "Removing an assertion makes the test pass in more situations, so it stops "
                        "protecting the behaviour it used to protect."
                    ),
                    fix=(
                        "Put the assertion back. If the behaviour genuinely changed, replace it with "
                        "an assertion on the new expected value."
                    ),
                    comment="Why was this assertion removed? Can we keep an equivalent one?",
                )
            )
    return out


def rule_path_traversal(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    for line in file.added_lines:
        text = line.text
        if "os.path.join" not in text and "path.join" not in text and "Path(" not in text:
            continue
        low = text.lower()
        if not any(word in low for word in ("request", "param", "args", "query", "input", "filename", "name")):
            continue
        out.append(
            Finding(
                rule="path_traversal",
                axis="security",
                severity="high",
                title="File path built from request data",
                path=file.path,
                line=line.new_no,
                evidence=text,
                why=(
                    "A name containing ../ lets a caller read or write outside the intended "
                    "directory, which is remote file disclosure or remote file write."
                ),
                fix=(
                    "Resolve the path and check that it is inside the allowed base directory "
                    "(Path(base).resolve() and is_relative_to), or use an allow list of names."
                ),
                comment="Can we confirm this path stays inside the base directory?",
            )
        )
    return out


BLOCK_RULES: List[Callable[[DiffFile, DiffSet], List[Finding]]] = [
    rule_except_swallow,
    rule_return_in_finally,
    rule_infinite_loop,
    rule_n_plus_one,
    rule_http_in_loop,
    rule_membership_in_loop,
    rule_string_concat_in_loop,
    rule_regex_in_loop,
    rule_file_open_in_loop,
    rule_sort_in_loop,
    rule_long_function,
    rule_empty_test,
    rule_closure_in_loop,
    rule_promise_without_catch,
    rule_unreachable_else,
    rule_weak_hash,
    rule_insecure_random,
    rule_float_money,
    rule_path_traversal,
    rule_removed_assertion,
]


# --------------------------------------------------------------------------
# Diff level rules (breaking changes, coverage, duplication)
# --------------------------------------------------------------------------

DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)")
CLASS_RE = re.compile(r"^\s*class\s+(?P<name>\w+)")
ROUTE_RE = re.compile(r"@[A-Za-z_][\w]*\.(?:route|get|post|put|delete|patch|websocket)\s*\(")
FUNC_RE = re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+(?P<name>\w+)\s*\((?P<args>[^)]*)\)")
GO_FUNC_RE = re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?(?P<name>\w+)\s*\((?P<args>[^)]*)\)")


def _symbols(lines, pattern):
    found = {}
    for line in lines:
        m = pattern.match(line.text)
        if m:
            found[m.group("name")] = m.groupdict().get("args", "")
    return found


def rule_removed_public_symbol(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    if file.category != "source":
        return out
    if file.status == "deleted":
        # The whole file is gone; the file_deleted rule already covers that.
        return out
    removed = file.removed_lines
    if not removed:
        return out
    added_names = set()
    for line in file.added_lines:
        for pattern in (DEF_RE, FUNC_RE, GO_FUNC_RE):
            m = pattern.match(line.text)
            if m:
                added_names.add(m.group("name"))
    for line in removed:
        text = line.text
        m = DEF_RE.match(text) or FUNC_RE.match(text) or GO_FUNC_RE.match(text)
        if m:
            name = m.group("name")
            if name.startswith("_") or name in added_names:
                continue
            out.append(
                Finding(
                    rule="public_symbol_removed",
                    axis="maintainability",
                    severity="high",
                    title="Function removed: " + name,
                    path=file.path,
                    line=line.old_no,
                    evidence=text,
                    why=(
                        "Removing a function from a shipped module breaks every caller that is not "
                        "in this diff, including other teams and published packages."
                    ),
                    fix=(
                        "Keep the old function as a thin wrapper that calls the new one and logs a "
                        "deprecation warning, then remove it in a later release."
                    ),
                    comment="Can we keep " + name + " as a deprecated wrapper for one release?",
                )
            )
            continue
        cm = CLASS_RE.match(text)
        if cm and cm.group("name") not in added_names:
            out.append(
                Finding(
                    rule="public_class_removed",
                    axis="maintainability",
                    severity="high",
                    title="Class removed: " + cm.group("name"),
                    path=file.path,
                    line=line.old_no,
                    evidence=text,
                    why="Removing a public class breaks every import of it.",
                    fix="Deprecate it first: keep the class and have it subclass or wrap the new one.",
                )
            )
            continue
        if ROUTE_RE.search(text):
            out.append(
                Finding(
                    rule="route_removed",
                    axis="maintainability",
                    severity="high",
                    title="HTTP route removed",
                    path=file.path,
                    line=line.old_no,
                    evidence=text,
                    why=(
                        "Removing a route changes the public API. Clients get a 404 with no warning "
                        "and no deprecation period."
                    ),
                    fix="Keep the route returning 410 Gone with a pointer to the replacement.",
                )
            )
    return out


def rule_changed_signature(file: DiffFile, diff: DiffSet) -> List[Finding]:
    out = []
    if file.category != "source":
        return out
    if file.status == "deleted":
        return out
    old = {}
    new = {}
    for line in file.removed_lines:
        m = DEF_RE.match(line.text) or FUNC_RE.match(line.text) or GO_FUNC_RE.match(line.text)
        if m:
            old[m.group("name")] = (m.groupdict().get("args", "") or "").strip()
    for line in file.added_lines:
        m = DEF_RE.match(line.text) or FUNC_RE.match(line.text) or GO_FUNC_RE.match(line.text)
        if m:
            new[m.group("name")] = (m.groupdict().get("args", "") or "").strip()
    for name, new_args in new.items():
        if name in old and old[name] != new_args:
            out.append(
                Finding(
                    rule="signature_changed",
                    axis="maintainability",
                    severity="high",
                    title="Signature changed: " + name,
                    path=file.path,
                    line=None,
                    evidence=name + "(" + new_args + ")",
                    why=(
                        "The parameter list changed, so every existing call site now passes the "
                        "wrong arguments or fails outright."
                    ),
                    fix=(
                        "Add the new parameter with a default, or accept keyword arguments so old "
                        "calls keep working."
                    ),
                    comment="This signature change breaks existing callers - can we keep it backwards compatible?",
                )
            )
    return out


def rule_deleted_file(diff: DiffSet) -> List[Finding]:
    out = []
    for file in diff.files:
        if file.status != "deleted":
            continue
        if file.category != "source":
            continue
        out.append(
            Finding(
                rule="file_deleted",
                axis="maintainability",
                severity="high",
                title="Source file deleted: " + file.path,
                path=file.path,
                line=None,
                evidence="deleted file mode: " + file.path,
                why=(
                    "Deleting a module in the same change that uses its replacement is how "
                    "imports start failing in places the diff does not show."
                ),
                fix="Move the file instead of deleting it, and fix the imports in the same commit.",
            )
        )
    return out


def rule_no_tests_changed(diff: DiffSet) -> List[Finding]:
    out = []
    source = diff.source_files
    if not source:
        return out
    if diff.test_files:
        return out
    logic = 0
    for f in source:
        for line in f.added_lines:
            if re.search(r"\b(def |function |class |func |=>|\breturn\b|\bif\b)", line.text):
                logic += 1
                break
    if logic == 0:
        return out
    paths = ", ".join(f.path for f in source[:4])
    out.append(
        Finding(
            rule="no_tests_changed",
            axis="testing",
            severity="high",
            title="Behaviour changed with no test changes",
            path=paths,
            line=None,
            evidence="files changed: " + paths,
            why=(
                "The diff changes behaviour and touches no test file, so nothing verifies the "
                "change. A regression lands silently and the next person finds it in production."
            ),
            fix="Add a test that fails before this change and passes after it.",
            comment="Could we add a test for this change in the same PR?",
        )
    )
    return out


def rule_new_function_untested(diff: DiffSet) -> List[Finding]:
    out = []
    if diff.test_files:
        return out
    for file in diff.source_files:
        for line in file.added_lines:
            m = DEF_RE.match(line.text) or FUNC_RE.match(line.text) or GO_FUNC_RE.match(line.text)
            if not m:
                continue
            name = m.group("name")
            if name.startswith("_") or name.startswith("test"):
                continue
            out.append(
                Finding(
                    rule="new_public_function_untested",
                    axis="testing",
                    severity="medium",
                    title="New public function with no test: " + name,
                    path=file.path,
                    line=line.new_no,
                    evidence=line.text,
                    why=(
                        "A new public function is new behaviour. Without a test, nothing says what "
                        "it is supposed to do and nothing says it still does it next month."
                    ),
                    fix="Add a test that exercises " + name + " and its error path.",
                    comment="Can we add a test for " + name + "?",
                )
            )
            break
    return out


def rule_duplicated_block(diff: DiffSet) -> List[Finding]:
    out = []
    window = 6
    seen = {}
    for file in diff.files:
        if file.is_generated:
            continue
        lines = [l.text.strip() for l in file.added_lines if l.text.strip()]
        for i in range(len(lines) - window + 1):
            block = lines[i : i + window]
            if sum(1 for b in block if b) < window:
                continue
            key = "\n".join(block)
            if key in seen:
                out.append(
                    Finding(
                        rule="duplicated_code_block",
                        axis="maintainability",
                        severity="medium",
                        title="Duplicated block of code",
                        path=file.path,
                        line=None,
                        evidence=" / ".join(block[:3]) + " ...",
                        why=(
                            "The same block appears twice in this change. Duplicated logic drifts: "
                            "the bug gets fixed in one copy and not the other."
                        ),
                        fix="Extract the repeated block into one function or constant and call it from both places.",
                        comment="This block is duplicated in the same diff - can we extract it?",
                    )
                )
                seen[key] = True
                break
            seen[key] = False
    # keep only the first report per file
    unique = []
    paths = set()
    for f in out:
        if f.path in paths:
            continue
        paths.add(f.path)
        unique.append(f)
    return unique


def rule_generated_and_large_files(diff: DiffSet) -> List[Finding]:
    out = []
    for file in diff.files:
        if file.is_generated:
            out.append(
                Finding(
                    rule="generated_file_changed",
                    axis="maintainability",
                    severity="low",
                    title="Generated or vendored file changed: " + file.path,
                    path=file.path,
                    line=None,
                    evidence=file.path,
                    why=(
                        "Generated files are not reviewed by humans and they get clobbered by the "
                        "next generator run, so the change is invisible to the reviewer."
                    ),
                    fix="Regenerate the file from its source and review the source instead.",
                )
            )
            continue
        length = file.estimated_length
        if length >= 500 and file.additions >= 20:
            out.append(
                Finding(
                    rule="large_file_growth",
                    axis="maintainability",
                    severity="medium",
                    title="Large file keeps growing: " + file.path,
                    path=file.path,
                    line=None,
                    evidence="file is about " + str(length) + " lines after this change",
                    why=(
                        "A file this big has too many reasons to change, so every future edit is a "
                        "merge conflict waiting to happen."
                    ),
                    fix="Split the file along its natural seams as part of this change.",
                    comment="This file is around " + str(length) + " lines - worth splitting?",
                )
            )
        if file.additions + file.deletions >= 250:
            out.append(
                Finding(
                    rule="noisy_mechanical_diff",
                    axis="maintainability",
                    severity="low",
                    title="Very large diff to review: " + file.path,
                    path=file.path,
                    line=None,
                    evidence=str(file.additions) + " additions, " + str(file.deletions) + " deletions",
                    why=(
                        "A diff this size is not reviewed line by line, so a real problem hidden "
                        "inside it is not going to be found by reading."
                    ),
                    fix="Split the change into reviewable pieces, or do the mechanical part in a separate commit.",
                )
            )
    return out


DIFF_RULES: List[Callable[[DiffSet], List[Finding]]] = [
    rule_no_tests_changed,
    rule_new_function_untested,
    rule_deleted_file,
    rule_duplicated_block,
    rule_generated_and_large_files,
]


def file_findings(file: DiffFile, diff: DiffSet) -> List[Finding]:
    """Run every line and block rule against one file."""
    out: List[Finding] = []
    if file.is_binary:
        return out
    for rule in LINE_RULES:
        cats = rule.get("cats")
        langs = rule.get("langs")
        if cats and file.category not in cats:
            continue
        if langs and file.language not in langs:
            continue
        pattern = re.compile(rule["pattern"])
        exclude = re.compile(rule["exclude"]) if rule.get("exclude") else None
        for line in file.added_lines:
            text = line.text
            if not text.strip():
                continue
            if not pattern.search(text):
                continue
            if exclude is not None and exclude.search(text):
                continue
            out.append(_finding(rule, file.path, line.new_no, text))
    for block_rule in BLOCK_RULES:
        out.extend(block_rule(file, diff))
    out.extend(rule_removed_public_symbol(file, diff))
    out.extend(rule_changed_signature(file, diff))
    return out


def diff_findings(diff: DiffSet) -> List[Finding]:
    out: List[Finding] = []
    for rule in DIFF_RULES:
        out.extend(rule(diff))
    return out


def all_findings(diff: DiffSet) -> List[Finding]:
    out: List[Finding] = []
    for file in diff.files:
        out.extend(file_findings(file, diff))
    out.extend(diff_findings(diff))
    return out
