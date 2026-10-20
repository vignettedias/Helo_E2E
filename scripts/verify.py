#!/usr/bin/env python3
"""Run every verification suite and record exactly what happened.

    python scripts/verify.py                  # everything that can run here
    python scripts/verify.py --skip flutter   # leave a suite out (recorded as NOT RUN)
    python scripts/verify.py --flutter C:/flutter/bin/flutter.bat

Writes:
    reports/verification.json   machine-readable results (read by the app's
                                Verification dashboard via /verification.json)
    reports/dashboard.html      the same results as a standalone page

Rules this script follows, because a security dashboard that overstates is
worse than none:
  * A status comes only from a suite that actually ran in this invocation.
    Nothing is copied from earlier runs, docs or CI.
  * A missing tool is NOT RUN, never PASS. A suite whose prerequisite failed
    is BLOCKED.
  * Per-test results are parsed from the runners' own machine output (JUnit
    XML, the Flutter JSON reporter); a suite that exits non-zero is FAIL even
    if every parsed test passed.

Standard library only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
REPORTS = REPO / "reports"
ANSI = re.compile(r"\x1b\[[0-9;]*m")

PASS, FAIL, BLOCKED, NOT_RUN = "PASS", "FAIL", "BLOCKED", "NOT RUN"


@dataclass
class Suite:
    key: str
    name: str
    description: str
    command: str = ""
    status: str = NOT_RUN
    passed: int = 0
    total: int = 0
    duration_s: float | None = None
    tests: list[dict] = field(default_factory=list)
    note: str = ""

    def to_json(self) -> dict:
        d = {
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "command": self.command or None,
            "status": self.status,
            "passed": self.passed,
            "total": self.total,
            "duration_s": self.duration_s,
            "tests": self.tests,
        }
        if self.note:
            d["note"] = self.note
        return d


def run(cmd: list[str], cwd: Path, timeout: int, env: dict | None = None) -> tuple[int, str, float]:
    start = time.monotonic()
    try:
        p = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, env={**os.environ, **(env or {})},
        )
        out, code = (p.stdout or "") + (p.stderr or ""), p.returncode
    except subprocess.TimeoutExpired as e:
        out = f"{e.stdout or ''}{e.stderr or ''}\nTIMEOUT after {timeout} s"
        code = -1
    return code, out, round(time.monotonic() - start, 1)


def tail(text: str, n: int = 1500) -> str:
    text = ANSI.sub("", text).strip()
    return text if len(text) <= n else "…" + text[-n:]


def finish(s: Suite, code: int, out: str) -> None:
    """Status from the exit code AND the parsed tests; either failing is FAIL."""
    s.total = len(s.tests)
    s.passed = sum(1 for t in s.tests if t["status"] == PASS)
    failed = any(t["status"] == FAIL for t in s.tests)
    if code == 0 and not failed and s.total > 0:
        s.status = PASS
    else:
        s.status = FAIL
        if code != 0 and not failed:
            # The runner failed without a parsed failing test (crash, timeout,
            # collection error): show its output as a test so it is visible.
            s.tests.append({"name": "runner exit status", "status": FAIL,
                            "details": f"exit code {code}\n{tail(out)}"})
            s.total += 1


# --------------------------------------------------------------- parsers

def parse_junit(path: Path) -> list[dict]:
    if not path.exists():
        return []
    root = ET.parse(path).getroot()
    tests = []
    for case in root.iter("testcase"):
        name = case.get("name", "?")
        cls = case.get("classname", "")
        full = f"{cls}::{name}" if cls and cls not in name else name
        bad = case.find("failure")
        if bad is None:
            bad = case.find("error")
        if bad is not None:
            msg = (bad.get("message") or "") + "\n" + (bad.text or "")
            tests.append({"name": full, "status": FAIL, "details": tail(msg, 600)})
        elif case.find("skipped") is not None:
            tests.append({"name": full, "status": NOT_RUN,
                          "details": case.find("skipped").get("message")})
        else:
            tests.append({"name": full, "status": PASS})
    return tests


def parse_flutter_json(out: str) -> list[dict]:
    names: dict[int, str] = {}
    errors: dict[int, str] = {}
    tests = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = ev.get("type")
        if kind == "testStart":
            t = ev["test"]
            names[t["id"]] = t["name"]
        elif kind == "error":
            errors[ev["testID"]] = errors.get(ev["testID"], "") + ev.get("error", "")
        elif kind == "testDone":
            if ev.get("hidden"):
                continue  # loading / setUpAll pseudo-tests
            tid = ev["testID"]
            name = names.get(tid, f"test {tid}")
            if ev.get("skipped"):
                tests.append({"name": name, "status": NOT_RUN, "details": "skipped"})
            elif ev.get("result") == "success":
                tests.append({"name": name, "status": PASS})
            else:
                tests.append({"name": name, "status": FAIL, "details": tail(errors.get(tid, ""), 600)})
    return tests


CHECK_LINE = re.compile(r"^\s*\[(PASS|FAIL)\]\s+(.*)$")


def parse_check_lines(out: str) -> list[dict]:
    tests = []
    for line in ANSI.sub("", out).splitlines():
        m = CHECK_LINE.match(line)
        if m:
            tests.append({"name": m.group(2).strip(), "status": m.group(1)})
    return tests


# ---------------------------------------------------------------- suites

def suite_pytest(key: str, folder: str, name: str, description: str, tmp: Path) -> Suite:
    xml = tmp / f"{key}.xml"
    cmd = [sys.executable, "-m", "pytest", f"tests/{folder}", "-q", "-p", "no:cacheprovider",
           f"--junitxml={xml}"]
    s = Suite(key, name, description, f"python -m pytest tests/{folder} -q")
    code, out, s.duration_s = run(cmd, REPO, timeout=1800)
    s.tests = parse_junit(xml)
    finish(s, code, out)
    return s


def suite_vectors() -> Suite:
    s = Suite("vectors", "Cryptographic test vectors reproduce byte-exactly",
              "Regenerates every committed vector (X3DH, PQXDH, ratchet, padding, attachments) and "
              "compares bytes. A diff means derived keys changed.",
              "python scripts/generate_test_vectors.py --check")
    code, out, s.duration_s = run([sys.executable, "scripts/generate_test_vectors.py", "--check"],
                                  REPO, timeout=600)
    s.tests = [{"name": "tests/vectors/*.json reproduce", "status": PASS if code == 0 else FAIL,
                "details": tail(out, 400)}]
    finish(s, code, out)
    return s


def suite_relay(node: str | None, tmp: Path) -> Suite:
    s = Suite("relay", "Relay (Node) test suite",
              "Real HTTP server per test: auth, device-bound sending (A1), prekeys incl. PQ, "
              "long-poll, groups fan-out, attachments, blocks, rate limits, migrations.",
              "cd backend && node --test test/relay.test.js test/relay_v2.test.js")
    if node is None:
        s.note = "node not found on PATH"
        return s
    xml = tmp / "relay.xml"
    cmd = [node, "--test", "--test-reporter=junit", f"--test-reporter-destination={xml}",
           "test/relay.test.js", "test/relay_v2.test.js"]
    code, out, s.duration_s = run(cmd, REPO / "backend", timeout=900)
    s.tests = parse_junit(xml)
    finish(s, code, out)
    return s


def suite_e2e(node: str | None) -> Suite:
    s = Suite("integration_e2e", "End to end: reference client through the real relay",
              "Starts the relay, runs a PQXDH conversation with the Python reference client, then "
              "opens the relay database as an attacker would and searches it for plaintext and keys.",
              "python scripts/integration_e2e.py")
    if node is None:
        s.status, s.note = BLOCKED, "needs node (the relay) on PATH"
        return s
    code, out, s.duration_s = run([sys.executable, "scripts/integration_e2e.py"], REPO, timeout=900)
    s.tests = parse_check_lines(out)
    finish(s, code, out)
    return s


def suite_ruff(ruff: str | None) -> Suite:
    s = Suite("lint_python", "Python lint (ruff)", "Static checks over crypto/, tests/, scripts/.",
              "ruff check crypto/ tests/ scripts/")
    if ruff is None:
        s.note = "ruff not found (pass --ruff or put it on PATH)"
        return s
    code, out, s.duration_s = run([ruff, "check", "crypto/", "tests/", "scripts/"], REPO, timeout=300)
    s.tests = [{"name": "ruff check", "status": PASS if code == 0 else FAIL, "details": tail(out, 800)}]
    finish(s, code, out)
    return s


def suite_flutter_analyze(flutter: str | None) -> Suite:
    s = Suite("flutter_analyze", "Dart static analysis", "flutter analyze over the client.",
              "cd mobile && flutter analyze")
    if flutter is None:
        s.note = "flutter not found (pass --flutter)"
        return s
    code, out, s.duration_s = run([flutter, "analyze", "--no-pub"], REPO / "mobile", timeout=600)
    s.tests = [{"name": "flutter analyze", "status": PASS if code == 0 else FAIL, "details": tail(out, 800)}]
    finish(s, code, out)
    return s


def suite_flutter_test(flutter: str | None, node: str | None) -> Suite:
    s = Suite("flutter_test", "Client (Dart) tests",
              "Dart crypto vs. the Python vectors, protocol v2 conformance, Messenger end to end and "
              "chat-screen widget tests against the REAL relay process.",
              "cd mobile && flutter test")
    if flutter is None:
        s.note = "flutter not found (pass --flutter)"
        return s
    if node is None:
        s.status, s.note = BLOCKED, "Messenger tests start the relay: node must be on PATH"
        return s
    code, out, s.duration_s = run([flutter, "test", "--no-pub", "--reporter", "json"],
                                  REPO / "mobile", timeout=1800)
    s.tests = parse_flutter_json(out)
    finish(s, code, out)
    return s


# ---------------------------------------------------------------- output

def tool_version(cmd: list[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                             timeout=60).stdout.strip()
        return out.splitlines()[0] if out else "?"
    except (OSError, subprocess.SubprocessError):
        return "?"


def environment(node: str | None, flutter: str | None) -> str:
    parts = [f"{platform.system()} {platform.release()}", f"Python {platform.python_version()}"]
    try:
        import cryptography
        from cryptography.hazmat.backends.openssl.backend import backend

        parts.append(f"cryptography {cryptography.__version__} ({backend.openssl_version_text()})")
    except Exception:
        pass
    if node:
        parts.append(f"Node {tool_version([node, '--version'])}")
    if flutter:
        parts.append(tool_version([flutter, "--version"]).split("•")[0].strip())
    return " · ".join(parts)


def render_html(report: dict) -> str:
    def badge(status: str) -> str:
        return f'<span class="b {status.replace(" ", "-").lower()}">{html.escape(status)}</span>'

    rows = []
    for s in report["suites"]:
        tests = "".join(
            f'<li>{badge(t["status"])} {html.escape(t["name"])}'
            + (f'<pre>{html.escape(str(t["details"]))}</pre>'
               if t.get("details") and t["status"] != PASS else "")
            + "</li>"
            for t in s["tests"]
        )
        meta = f'{s["passed"]}/{s["total"]} passed'
        if s["duration_s"] is not None:
            meta += f' · {s["duration_s"]} s'
        if s.get("note"):
            meta += f' · {html.escape(s["note"])}'
        rows.append(
            f'<details{" open" if s["status"] == FAIL else ""}><summary>{badge(s["status"])} '
            f'<b>{html.escape(s["name"])}</b> <span class="m">{meta}</span></summary>'
            f'<p>{html.escape(s["description"])}</p>'
            + (f'<code>$ {html.escape(s["command"])}</code>' if s.get("command") else "")
            + f"<ul>{tests}</ul></details>"
        )
    totals = " ".join(f'{badge(k)} {v}' for k, v in report["totals"].items())
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HELO Verification</title>
<style>
:root {{ --bg:#f6f7f9; --fg:#14181f; --muted:#5b6472; --card:#fff; --line:#e1e4ea;
  --pass:#137a3a; --fail:#b42318; --warn:#9a6700; --idle:#5b6472; }}
@media (prefers-color-scheme: dark) {{ :root:not([data-theme="light"]) {{
  --bg:#0f141a; --fg:#e6e9ee; --muted:#9aa4b2; --card:#161c24; --line:#273040;
  --pass:#4ade80; --fail:#f87171; --warn:#fbbf24; --idle:#9aa4b2; }} }}
:root[data-theme="dark"] {{ --bg:#0f141a; --fg:#e6e9ee; --muted:#9aa4b2; --card:#161c24; --line:#273040;
  --pass:#4ade80; --fail:#f87171; --warn:#fbbf24; --idle:#9aa4b2; }}
body {{ margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui, sans-serif; }}
main {{ max-width:900px; margin:0 auto; padding:24px 16px; }}
details {{ background:var(--card); border:1px solid var(--line); border-radius:12px; margin:10px 0; padding:10px 14px; }}
summary {{ cursor:pointer; }}
.m, p {{ color:var(--muted); font-size:13px; }}
code {{ display:block; font-size:12.5px; color:var(--muted); margin:6px 0; overflow-wrap:anywhere; }}
ul {{ list-style:none; padding-left:0; font-size:13px; }}
li {{ padding:2px 0; overflow-wrap:anywhere; }}
pre {{ white-space:pre-wrap; font-size:12px; color:var(--muted); margin:4px 0 8px 0; }}
.b {{ display:inline-block; min-width:62px; text-align:center; border-radius:6px; font-size:11px;
  font-weight:700; padding:1px 6px; border:1px solid currentColor; }}
.pass {{ color:var(--pass); }} .fail {{ color:var(--fail); }} .blocked {{ color:var(--warn); }}
.not-run, .experimental {{ color:var(--idle); }}
</style></head><body><main>
<h1>HELO verification</h1>
<p>Run {html.escape(report["generated_at"])} · {html.escape(report["environment"])}</p>
<p>{totals}</p>
<p>A passing test is evidence for the specific behaviour it checks — not proof that every security
property holds. Suites marked NOT RUN or BLOCKED did not run in this invocation.</p>
{"".join(rows)}
</main></body></html>
"""


def find_tool(explicit: str | None, names: list[str]) -> str | None:
    if explicit:
        return explicit if Path(explicit).exists() or shutil.which(explicit) else None
    for n in names:
        found = shutil.which(n)
        if found:
            return found
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--skip", action="append", default=[],
                    help="suite key to skip: unit, adversarial, property, integration, vectors, relay, "
                         "integration_e2e, lint_python, flutter_analyze, flutter_test, flutter")
    ap.add_argument("--flutter", help="path to the flutter executable")
    ap.add_argument("--ruff", help="path to the ruff executable")
    args = ap.parse_args()
    skip = set(args.skip)
    if "flutter" in skip:
        skip |= {"flutter_analyze", "flutter_test"}

    node = shutil.which("node")
    flutter = find_tool(args.flutter or os.environ.get("HELO_FLUTTER"), ["flutter", "flutter.bat"])
    ruff = find_tool(args.ruff or os.environ.get("HELO_RUFF"), ["ruff"])

    plan = [
        ("unit", lambda t: suite_pytest("unit", "unit", "Protocol unit tests (Python reference)",
                                        "X3DH/PQXDH, double ratchet, envelopes, padding, attachments, "
                                        "session persistence.", t)),
        ("adversarial", lambda t: suite_pytest("adversarial", "adversarial", "Adversarial tests",
                                               "Tampering, replay, reordering, downgrade, key "
                                               "substitution, malformed input.", t)),
        ("property", lambda t: suite_pytest("property", "property", "Property-based tests (Hypothesis)",
                                            "Randomised round-trip and invariant checks.", t)),
        ("integration", lambda t: suite_pytest("integration", "integration", "Integration & vector tests",
                                               "Multi-party flows and committed-vector conformance.", t)),
        ("vectors", lambda t: suite_vectors()),
        ("relay", lambda t: suite_relay(node, t)),
        ("integration_e2e", lambda t: suite_e2e(node)),
        ("lint_python", lambda t: suite_ruff(ruff)),
        ("flutter_analyze", lambda t: suite_flutter_analyze(flutter)),
        ("flutter_test", lambda t: suite_flutter_test(flutter, node)),
    ]

    suites: list[Suite] = []
    with tempfile.TemporaryDirectory(prefix="helo-verify-") as tmp:
        for key, make in plan:
            if key in skip:
                s = Suite(key, key, "Skipped on the command line.", status=NOT_RUN, note="--skip")
            else:
                print(f"- {key} ...", end=" ", flush=True)
                s = make(Path(tmp))
            print(f"{s.status} ({s.passed}/{s.total})" + (f" - {s.note}" if s.note else ""), flush=True)
            suites.append(s)

    totals: dict[str, int] = {}
    for s in suites:
        totals[s.status] = totals.get(s.status, 0) + 1
    report = {
        "schema": 1,
        "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "environment": environment(node, flutter),
        "totals": totals,
        "tests_total": sum(s.total for s in suites),
        "tests_passed": sum(s.passed for s in suites),
        "suites": [s.to_json() for s in suites],
    }
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "verification.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                                               encoding="utf-8", newline="\n")
    (REPORTS / "dashboard.html").write_text(render_html(report), encoding="utf-8", newline="\n")
    print(f"\n{report['tests_passed']}/{report['tests_total']} tests passed; suites: "
          + ", ".join(f"{v} {k}" for k, v in totals.items()))
    print(f"wrote {REPORTS / 'verification.json'} and {REPORTS / 'dashboard.html'}")
    return 1 if totals.get(FAIL) else 0


if __name__ == "__main__":
    sys.exit(main())
