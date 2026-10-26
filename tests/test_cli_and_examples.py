"""The command line contract (exit codes 0/1/2/64), the shipped examples, and
repository hygiene (PyYAML is only ever loaded through a SafeLoader subclass)."""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from cti_report_lint.cli import main

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
EXAMPLES = ROOT / "examples"

PASSING = """---
date: 2026-09-01
findings:
  - {finding_type: PRIMARY, trust_score: 5, source_reliability: A, confirmed_by: []}
---
The tracked actor (who) deployed a ransomware payload (what) first seen
2026-02 (when) against the finance sector (where) for financial motivation
(why) via a phishing initial-access vector (how).
"""


def _write(tmp_path, text, name="report.md"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# ── exit codes for `check` ──────────────────────────────────────────────

def test_check_exit_0_on_pass(tmp_path):
    assert main(["check", str(_write(tmp_path, PASSING))]) == 0


def test_check_exit_1_on_block(tmp_path):
    assert main(["check", str(_write(tmp_path, "---\ntitle: t\n---\nnothing here.\n"))]) == 1


def test_check_exit_2_on_missing_report(tmp_path, capsys):
    assert main(["check", str(tmp_path / "no-such-report.md")]) == 2
    assert "NOT EVALUABLE" in capsys.readouterr().err


def test_check_exit_2_on_a_directory(tmp_path):
    assert main(["check", str(tmp_path)]) == 2


@pytest.mark.parametrize("argv", [
    ["--no-such-flag"],
    [],
    ["check"],
    ["check", "r.md", "--min-5w1h", "7"],
    ["check", "r.md", "--min-5w1h", "four"],
    ["check", "r.md", "--findings-required-from", "15/08/2026"],
    ["redact", "in.md"],                      # --map is required
])
def test_usage_error_is_64_not_2(argv):
    assert main(argv) == 64


def test_help_exits_0():
    assert main(["--help"]) == 0


def test_findings_required_from_flag_reaches_the_gate(tmp_path):
    p = _write(tmp_path, "---\ndate: 2026-08-01\n---\n" + PASSING.split("---\n", 2)[2],
               "old.md")
    assert main(["check", str(p)]) == 1                      # default: required
    assert main(["check", str(p), "--findings-required-from", "2026-08-15"]) == 0


def test_min_5w1h_flag_reaches_the_gate(tmp_path):
    p = _write(tmp_path, PASSING.replace("(why)", "").replace(
        "for financial motivation", ""))
    assert main(["check", str(p), "--min-5w1h", "6"]) == 1
    assert main(["check", str(p), "--min-5w1h", "5"]) == 0


def test_json_output_is_parseable(tmp_path, capsys):
    assert main(["check", str(_write(tmp_path, PASSING)), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["verified_ok"] is True and out["issues"] == []


# ── redact / restore ────────────────────────────────────────────────────

def test_cli_round_trip_lossless(tmp_path):
    text = "Mail jane.doe@example.com from 192.0.2.44 on 2026-09-20.\n"
    src = _write(tmp_path, text, "in.md")
    m, red, back = tmp_path / "map.json", tmp_path / "red.md", tmp_path / "back.md"
    assert main(["redact", str(src), "--map", str(m), "-o", str(red)]) == 0
    assert "jane.doe" not in red.read_text(encoding="utf-8")
    assert "2026-09-20" in red.read_text(encoding="utf-8")
    assert main(["restore", str(red), "--map", str(m), "-o", str(back)]) == 0
    assert back.read_text(encoding="utf-8") == text


def test_cli_restore_with_incomplete_map_exits_1(tmp_path):
    red = _write(tmp_path, "see [EMAIL_1#a1b2c3] and [EMAIL_2#a1b2c3]\n", "red.md")
    m = _write(tmp_path, json.dumps({"[EMAIL_1#a1b2c3]": "a@example.com"}), "map.json")
    out = tmp_path / "out.md"
    assert main(["restore", str(red), "--map", str(m), "-o", str(out)]) == 1
    assert not out.exists()          # nothing partially restored was written


def test_cli_restore_with_missing_map_exits_2(tmp_path):
    red = _write(tmp_path, "see [EMAIL_1]\n", "red.md")
    assert main(["restore", str(red), "--map", str(tmp_path / "nope.json")]) == 2


def test_cli_redact_with_missing_input_exits_2(tmp_path):
    assert main(["redact", str(tmp_path / "nope.md"),
                 "--map", str(tmp_path / "m.json")]) == 2


# ── the shipped examples ────────────────────────────────────────────────

def _check_json(path: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, "-m", "cti_report_lint", "check", str(path), "--json"],
        capture_output=True, text=True, env={"PYTHONPATH": str(SRC)})
    result = json.loads(proc.stdout)
    result["_exit"] = proc.returncode
    return result


def test_example_before_fails_with_each_expected_issue():
    r = _check_json(EXAMPLES / "incident-report-before.md")
    assert r["_exit"] == 1
    issues = r["issues"]

    def has(prefix, needle):
        return any(i.startswith(prefix) and needle in i for i in issues)

    assert has("judgment:", "hedged likelihood range")
    assert has("judgment:", "bare percentage")
    assert has("judgment:", "absolute language")
    assert has("coverage:", "5W1H only")
    assert has("findings[0]:", "exceeds evidence ceiling")
    assert has("conflicts[0]:", "OPEN CRITICAL VALUE_MISMATCH")


def test_example_after_passes():
    r = _check_json(EXAMPLES / "incident-report-after.md")
    assert r["_exit"] == 0, r["issues"]
    assert r["issues"] == []
    assert r["coverage_5w1h"] == 6
    assert r["conflicts"] and all(not c["open"] for c in r["conflicts"])


def test_examples_use_only_documentation_addresses():
    """RFC 5737 IPv4 ranges and example.com mail only: no real infrastructure."""
    for name in ("incident-report-before.md", "incident-report-after.md"):
        text = (EXAMPLES / name).read_text(encoding="utf-8")
        for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
            assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")), ip
        for mail in re.findall(r"[\w.+-]+@([\w.-]+)", text):
            assert mail.rstrip(".") == "example.com", mail


# ── hygiene ─────────────────────────────────────────────────────────────

def _unsafe_yaml_loads(source: str) -> list[str]:
    """Names every yaml.load call in `source` whose Loader is not a class,
    defined in that source, that derives (through classes defined there) from
    yaml.SafeLoader / yaml.CSafeLoader. Any other yaml loader entry point is
    reported outright."""
    import ast
    tree = ast.parse(source)
    safe_roots = {"SafeLoader", "CSafeLoader"}
    derived: dict[str, bool] = {}

    def is_safe(name: str, seen=()) -> bool:
        if name in derived:
            return derived[name]
        cls = next((n for n in ast.walk(tree)
                    if isinstance(n, ast.ClassDef) and n.name == name), None)
        ok = False
        if cls is not None and name not in seen:
            for base in cls.bases:
                if (isinstance(base, ast.Attribute) and base.attr in safe_roots
                        and isinstance(base.value, ast.Name) and base.value.id == "yaml"):
                    ok = True
                elif isinstance(base, ast.Name) and is_safe(base.id, seen + (name,)):
                    ok = True
        derived[name] = ok
        return ok

    bad = []
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and isinstance(n.func.value, ast.Name) and n.func.value.id == "yaml"):
            continue
        fn = n.func.attr
        if fn in ("unsafe_load", "unsafe_load_all", "full_load", "full_load_all",
                  "load_all"):
            bad.append(f"yaml.{fn} at line {n.lineno}")
        elif fn == "load":
            loader = next((k.value for k in n.keywords if k.arg == "Loader"),
                          n.args[1] if len(n.args) > 1 else None)
            if not (isinstance(loader, ast.Name) and is_safe(loader.id)):
                bad.append(f"yaml.load at line {n.lineno} without a SafeLoader subclass")
    return bad


def test_yaml_load_must_pass_a_safeloader_subclass():
    """The pin itself, both directions: it accepts the strict loader and
    rejects each way of loading untrusted YAML unsafely."""
    good = ("import yaml\nclass L(yaml.SafeLoader):\n    pass\n"
            "class M(L):\n    pass\nyaml.load(t, Loader=M)\nyaml.safe_load(t)\n")
    assert _unsafe_yaml_loads(good) == []
    for bad in ("import yaml\nyaml.load(t)\n",
                "import yaml\nyaml.load(t, Loader=yaml.Loader)\n",
                "import yaml\nyaml.load(t, yaml.UnsafeLoader)\n",
                "import yaml\nclass L(yaml.Loader):\n    pass\nyaml.load(t, Loader=L)\n",
                "import yaml\nyaml.load(t, Loader=Undefined)\n",
                "import yaml\nyaml.unsafe_load(t)\n",
                "import yaml\nyaml.full_load(t)\n"):
        assert _unsafe_yaml_loads(bad), bad


def test_yaml_is_only_loaded_through_a_safeloader_subclass():
    """yaml.load on untrusted input can construct arbitrary objects. Report
    frontmatter is untrusted input, so every yaml.load in the package must
    name a SafeLoader subclass (the strict, duplicate-refusing loader)."""
    offenders = []
    for py in sorted((SRC / "cti_report_lint").glob("*.py")):
        offenders += [f"{py.name}: {m}" for m in
                      _unsafe_yaml_loads(py.read_text(encoding="utf-8"))]
    assert offenders == []
    import yaml
    from cti_report_lint import _yaml
    assert issubclass(_yaml._StrictLoader, yaml.SafeLoader)
    uses = [py.name for py in (SRC / "cti_report_lint").glob("*.py")
            if "load_strict(" in py.read_text(encoding="utf-8") and py.name != "_yaml.py"]
    assert len(uses) >= 2, "frontmatter readers must go through load_strict"


# ── map safety and the I/O contract ───────────────────────────────────



def test_redaction_map_is_private_whatever_the_umask(tmp_path):
    src = _write(tmp_path, "mail " + "a@b" + ".example.com\n", "in.md")
    m = tmp_path / "map.json"
    old = os.umask(0o002)
    try:
        assert main(["redact", str(src), "--map", str(m), "-o", str(tmp_path / "o.md")]) == 0
    finally:
        os.umask(old)
    assert stat.S_IMODE(m.stat().st_mode) == 0o600


def test_restored_output_is_private(tmp_path):
    src = _write(tmp_path, "mail " + "a@b" + ".example.com\n", "in.md")
    m, red, back = tmp_path / "map.json", tmp_path / "red.md", tmp_path / "back.md"
    assert main(["redact", str(src), "--map", str(m), "-o", str(red)]) == 0
    assert main(["restore", str(red), "--map", str(m), "-o", str(back)]) == 0
    assert back.read_text(encoding="utf-8") == src.read_text(encoding="utf-8")
    assert stat.S_IMODE(back.stat().st_mode) == 0o600


@pytest.mark.parametrize("which", ["map-is-input", "output-is-input", "output-is-map"])
def test_aliased_paths_are_a_usage_error(tmp_path, which):
    src = _write(tmp_path, "mail " + "a@b" + ".example.com\n", "in.md")
    m = tmp_path / "map.json"
    argv = {"map-is-input": ["redact", str(src), "--map", str(src)],
            "output-is-input": ["redact", str(src), "--map", str(m), "-o", str(src)],
            "output-is-map": ["redact", str(src), "--map", str(m), "-o", str(m)]}[which]
    before = src.read_text(encoding="utf-8")
    assert main(argv) == 64
    assert src.read_text(encoding="utf-8") == before


def test_redacting_twice_with_one_map_is_refused(tmp_path):
    src = _write(tmp_path, "mail " + "a@b" + ".example.com\n", "in.md")
    m, red = tmp_path / "map.json", tmp_path / "red.md"
    assert main(["redact", str(src), "--map", str(m), "-o", str(red)]) == 0
    assert main(["redact", str(red), "--map", str(m), "-o", str(tmp_path / "x.md")]) == 1


def test_a_malformed_map_is_not_evaluable(tmp_path):
    red = _write(tmp_path, "see [EMAIL_1#a1b2c3]\n", "red.md")
    m = _write(tmp_path, json.dumps({"[EMAIL_1#a1b2c3]": 7}), "map.json")
    assert main(["restore", str(red), "--map", str(m)]) == 2


def test_an_unwritable_output_is_not_evaluable_not_a_crash(tmp_path):
    src = _write(tmp_path, "benign text\n", "in.md")
    rc = main(["redact", str(src), "--map", str(tmp_path / "m.json"),
               "-o", str(tmp_path / "no-such-dir" / "o.md")])
    assert rc == 2


# ── README transcript check (examples/check_readme.py) ────────────────────

def _load_check_readme():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "check_readme", EXAMPLES / "check_readme.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_check_readme_catches_a_dropped_output_line():
    cr = _load_check_readme()
    shown = ["$ cti-report-lint check a.md", "a.md: PASS", "(exit 0)"]
    printed = ["noise", "$ cti-report-lint check a.md", "a.md: PASS",
               "  finding[0] PRIMARY strength 9.6", "(exit 0)", "more"]
    want, bad = cr.mismatches(shown, printed)
    assert len(want) == 1 and len(bad) == 1          # README dropped a line
    assert cr.mismatches(printed[1:5], printed)[1] == []
    assert cr.mismatches(["$ x", "out"], printed)[1]  # no (exit N): mismatch


def test_check_readme_passes_on_the_real_readme_and_fails_on_a_drifted_one(tmp_path):
    shim = tmp_path / "bin" / "cti-report-lint"
    shim.parent.mkdir()
    shim.write_text(f'#!/bin/sh\nPYTHONPATH="{SRC}" exec "{sys.executable}" '
                    '-m cti_report_lint "$@"\n')
    shim.chmod(0o755)
    env = {**os.environ, "PATH": f"{shim.parent}{os.pathsep}{os.environ['PATH']}"}
    run = lambda: subprocess.run([sys.executable, str(EXAMPLES / "check_readme.py")],
                                 env=env, capture_output=True, text=True)
    assert run().returncode == 0
    cr = _load_check_readme()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    block = "\n".join(cr.readme_block(readme))
    assert "finding[1] DERIVED" in block
    drifted = readme.replace("  finding[1] DERIVED strength 5.7 likelihood 'likely'\n", "")
    assert drifted != readme
    assert cr.mismatches(cr.readme_block(drifted), _demo_output(env))[1]


def _demo_output(env):
    return subprocess.run(["sh", str(EXAMPLES / "demo.sh")], env=env,
                          capture_output=True, text=True).stdout.splitlines()
