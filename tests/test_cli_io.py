"""Command-line I/O: byte-exact round trips, safe writes, strict maps."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from cti_report_lint.cli import main

BODY = "Contact a" + "@example.com from 203.0.113.7"


@pytest.mark.parametrize("nl", ["\n", "\r\n", "\r", "mixed"])
def test_file_round_trip_is_byte_exact_for_every_newline(tmp_path, nl):
    if nl == "mixed":
        raw = f"{BODY}\r\nsecond\nthird\rfourth\r\n"
    else:
        raw = f"{BODY}{nl}second line{nl}"
    src = tmp_path / "in.md"
    src.write_bytes(raw.encode("utf-8"))
    m, red, back = tmp_path / "m.json", tmp_path / "red.md", tmp_path / "back.md"
    assert main(["redact", str(src), "--map", str(m), "-o", str(red)]) == 0
    assert b"example.com" not in red.read_bytes()
    assert red.read_bytes().count(b"\r") == raw.count("\r")
    assert main(["restore", str(red), "--map", str(m), "-o", str(back)]) == 0
    assert back.read_bytes() == raw.encode("utf-8")


def test_stdout_round_trip_is_byte_exact(tmp_path):
    raw = f"{BODY}\r\nx\rY\n".encode()
    src = tmp_path / "in.md"
    src.write_bytes(raw)
    m = tmp_path / "m.json"
    cmd = [sys.executable, "-m", "cti_report_lint"]
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
    red = subprocess.run(cmd + ["redact", str(src), "--map", str(m)],
                         capture_output=True, env=env, check=True).stdout
    assert b"\r\n" in red and b"example.com" not in red
    (tmp_path / "red.md").write_bytes(red)
    back = subprocess.run(cmd + ["restore", str(tmp_path / "red.md"), "--map", str(m)],
                          capture_output=True, env=env, check=True).stdout
    assert back == raw


def test_hard_linked_output_is_refused_and_input_untouched(tmp_path):
    src = tmp_path / "h.txt"
    src.write_text("mail a" + "@example.com\n")
    alias = tmp_path / "h2.txt"
    os.link(src, alias)
    before = src.read_bytes()
    rc = main(["redact", str(src), "--map", str(tmp_path / "m.json"), "-o", str(alias)])
    assert rc == 64
    assert src.read_bytes() == before


def test_redacted_output_replaces_rather_than_writes_through(tmp_path):
    """Even an alias the check cannot see (a link made after the check) must
    not let redact write into another file's inode: output is replaced."""
    src = tmp_path / "in.txt"
    src.write_text("mail a" + "@example.com\n")
    out = tmp_path / "out.txt"
    other = tmp_path / "other.txt"
    out.write_text("old")
    os.link(out, other)
    assert main(["redact", str(src), "--map", str(tmp_path / "m.json"), "-o", str(out)]) == 0
    assert other.read_text() == "old"
    assert "EMAIL_1" in out.read_text()


def test_failed_redact_output_leaves_no_new_map(tmp_path):
    src = tmp_path / "a.txt"
    src.write_text("mail a" + "@example.com\n")
    m = tmp_path / "new.json"
    outdir = tmp_path / "outdir"
    outdir.mkdir()
    assert main(["redact", str(src), "--map", str(m), "-o", str(outdir)]) == 2
    assert not m.exists()
    # the per-map lock file is intentional and stays; nothing else may
    assert sorted(p.name for p in tmp_path.iterdir()
                  if not p.name.endswith(".lock")) == ["a.txt", "outdir"]


def test_failed_redact_output_leaves_a_seed_map_unchanged(tmp_path):
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("mail a" + "@example.com\n")
    b.write_text("mail b" + "@example.com\n")
    m = tmp_path / "m.json"
    assert main(["redact", str(a), "--map", str(m), "-o", str(tmp_path / "ra.txt")]) == 0
    seed = m.read_bytes()
    outdir = tmp_path / "outdir"
    outdir.mkdir()
    assert main(["redact", str(b), "--map", str(m), "-o", str(outdir)]) == 2
    assert m.read_bytes() == seed


def test_restore_of_mixed_maps_exits_1_and_writes_nothing(tmp_path):
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("mail a" + "@example.com\n")
    b.write_text("mail b" + "@example.com\n")
    ma, mb = tmp_path / "ma.json", tmp_path / "mb.json"
    assert main(["redact", str(a), "--map", str(ma), "-o", str(tmp_path / "ra")]) == 0
    assert main(["redact", str(b), "--map", str(mb), "-o", str(tmp_path / "rb")]) == 0
    both = tmp_path / "both.txt"
    both.write_text((tmp_path / "ra").read_text() + (tmp_path / "rb").read_text())
    out = tmp_path / "out.txt"
    assert main(["restore", str(both), "--map", str(ma), "-o", str(out)]) == 1
    assert not out.exists()


def test_duplicate_keys_in_a_map_are_refused(tmp_path):
    src = tmp_path / "in.txt"
    src.write_text("mail a" + "@example.com\n")
    m = tmp_path / "m.json"
    red = tmp_path / "red.txt"
    assert main(["redact", str(src), "--map", str(m), "-o", str(red)]) == 0
    key, val = next(iter(json.loads(m.read_text()).items()))
    m.write_text("{" + json.dumps(key) + ": " + json.dumps(val) + ", "
                 + json.dumps(key) + ": " + json.dumps("mallory@evil.example") + "}")
    out = tmp_path / "out.txt"
    assert main(["restore", str(red), "--map", str(m), "-o", str(out)]) == 2
    assert not out.exists()


@pytest.mark.parametrize("date", ["2026-99-99", "2026-02-30", "2026-13-01"])
def test_impossible_ratchet_date_is_a_usage_error(tmp_path, date):
    r = tmp_path / "r.md"
    r.write_text("text\n")
    assert main(["check", str(r), "--findings-required-from", date]) == 64


def test_check_verdict_and_issues_share_one_stream(tmp_path, capsys):
    r = tmp_path / "r.md"
    r.write_text("It is absolutely certain.\n")
    assert main(["check", str(r)]) == 1
    out, err = capsys.readouterr()
    assert "BLOCKED" in out and "judgment:" in out
    assert "BLOCKED" not in err


# ── undecodable input and directories ──────────────────────────────────

def test_check_undecodable_bytes_is_not_evaluable_with_a_named_cause(tmp_path, capsys):
    good = (Path(__file__).resolve().parents[1] / "examples"
            / "incident-report-after.md").read_bytes()
    r = tmp_path / "r.md"
    r.write_bytes(good + b"\xff")
    assert main(["check", str(r)]) == 2
    out, err = capsys.readouterr()
    assert "NOT EVALUABLE" in err and "UTF-8" in err and str(r) in err
    assert "PASS" not in out


def test_check_on_a_directory_says_so(tmp_path, capsys):
    assert main(["check", str(tmp_path)]) == 2
    err = capsys.readouterr().err
    assert "is a directory" in err and "not found" not in err


def test_validate_tree_lists_an_undecodable_file_as_unparseable(tmp_path):
    from cti_report_lint import findings
    (tmp_path / "bad.md").write_bytes(b"---\nfinding_type: PRIMARY\n---\n\xff\n")
    assert findings.validate_tree(tmp_path)["unparseable"] == [str(tmp_path / "bad.md")]


def test_restore_refusal_prints_plainly_not_as_a_repr(tmp_path, capsys):
    src = tmp_path / "in.md"
    src.write_text(BODY, encoding="utf-8")
    m, red = tmp_path / "m.json", tmp_path / "red.md"
    assert main(["redact", str(src), "--map", str(m), "-o", str(red)]) == 0
    m.write_text("{}", encoding="utf-8")   # an empty map cannot account for them
    capsys.readouterr()
    assert main(["restore", str(red), "--map", str(m)]) == 1
    err = capsys.readouterr().err.strip()
    assert err.startswith("restore:"), err
    assert not err.startswith(('"', "'")) and not err.endswith(('"', "'")), err
    assert "\\n" not in err and "\\u" not in err, err


def test_check_on_a_non_regular_file_says_so(capsys):
    assert main(["check", os.devnull]) == 2
    err = capsys.readouterr().err
    assert "not a regular file" in err and "not found" not in err
