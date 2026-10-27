"""Redact's writes to a shared map and to the output file: concurrent writers
on one map, and the two-artifact (output + map) commit with rollback."""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from unittest.mock import patch

from cti_report_lint import cli
from cti_report_lint.cli import main
from cti_report_lint.redact import restore

SEED = {"[EMAIL_1#abcdef]": "seed@example.com"}


def _redact(src, m, out):
    return main(["redact", str(src), "--map", str(m), "-o", str(out)])


# ---- concurrent writers on one shared map ---------------------------------

def test_sequential_shared_map_control(tmp_path):
    m = tmp_path / "m.json"
    m.write_text(json.dumps(SEED))
    originals = ["alice@example.com", "bob@example.org"]
    outs = []
    for i, v in enumerate(originals):
        (tmp_path / f"in{i}").write_text(v)
        assert _redact(tmp_path / f"in{i}", m, tmp_path / f"out{i}") == 0
        outs.append((tmp_path / f"out{i}").read_text())
    final = json.loads(m.read_text())
    assert [restore(o, final) for o in outs] == originals


def test_concurrent_writers_on_one_map_both_restore_exactly(tmp_path):
    m = tmp_path / "m.json"
    m.write_text(json.dumps(SEED))
    originals = ["alice@example.com", "bob@example.org"]
    for i, v in enumerate(originals):
        (tmp_path / f"in{i}").write_text(v)
    barrier = threading.Barrier(2)
    real = cli.redaction.redact

    def synced(text, seed):
        try:                       # both writers meet here only if unserialized
            barrier.wait(timeout=1)
        except threading.BrokenBarrierError:
            pass
        return real(text, seed)

    codes = [None, None]

    def run(i):
        codes[i] = _redact(tmp_path / f"in{i}", m, tmp_path / f"out{i}")

    with patch("cti_report_lint.cli.redaction.redact", side_effect=synced):
        ts = [threading.Thread(target=run, args=(i,)) for i in range(2)]
        [t.start() for t in ts]
        [t.join(30) for t in ts]
    assert codes == [0, 0]
    final = json.loads(m.read_text())
    got = [restore((tmp_path / f"out{i}").read_text(), final) for i in range(2)]
    assert got == originals


# ---- two-artifact commit: output and map land together or not at all ------

def _fixture(tmp_path):
    src, out, m = (tmp_path / n for n in ("src.txt", "out.txt", "m.json"))
    src.write_text("alice@example.com")
    out.write_text("PREVIOUS OUTPUT")
    m.write_text("{}")
    return src, out, m


def _failing_replace(target_name):
    real = os.replace

    def f(a, b):
        if Path(b).name == target_name:
            raise PermissionError("injected")
        return real(a, b)
    return f


def test_map_replace_failure_restores_previous_output(tmp_path, capsys):
    src, out, m = _fixture(tmp_path)
    with patch("cti_report_lint.cli.os.replace", side_effect=_failing_replace("m.json")):
        rc = _redact(src, m, out)
    assert rc == 2
    assert out.read_text() == "PREVIOUS OUTPUT"
    assert m.read_text() == "{}"
    assert "Nothing was changed" in capsys.readouterr().err
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]


def test_map_replace_failure_with_no_previous_output_leaves_none(tmp_path):
    src, out, m = _fixture(tmp_path)
    out.unlink()
    with patch("cti_report_lint.cli.os.replace", side_effect=_failing_replace("m.json")):
        assert _redact(src, m, out) == 2
    assert not out.exists()


def test_output_replace_failure_changes_nothing(tmp_path):
    src, out, m = _fixture(tmp_path)
    with patch("cti_report_lint.cli.os.replace", side_effect=_failing_replace("out.txt")):
        assert _redact(src, m, out) == 2
    assert out.read_text() == "PREVIOUS OUTPUT" and m.read_text() == "{}"


def test_stage_failure_changes_nothing(tmp_path):
    src, out, m = _fixture(tmp_path)
    real = cli._stage
    calls = []

    def stage(path, text, *, private):
        calls.append(path)
        if len(calls) == 2:
            raise OSError("injected stage failure")
        return real(path, text, private=private)
    with patch("cti_report_lint.cli._stage", side_effect=stage):
        assert _redact(src, m, out) == 2
    assert out.read_text() == "PREVIOUS OUTPUT" and m.read_text() == "{}"
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]


def test_failed_rollback_is_reported_not_denied(tmp_path, capsys):
    src, out, m = _fixture(tmp_path)
    real = os.replace

    def f(a, b):
        if Path(b).name == "m.json":
            raise PermissionError("map")
        if Path(b).name == "out.txt" and ".bak" in Path(a).name:
            raise PermissionError("rollback")
        return real(a, b)
    with patch("cti_report_lint.cli.os.replace", side_effect=f):
        assert _redact(src, m, out) == 2
    err = capsys.readouterr().err
    assert "Nothing was changed" not in err
    assert "out.txt WAS CHANGED" in err
    kept = [p for p in tmp_path.iterdir() if p.name.endswith(".bak.tmp")]
    assert [p.read_text() for p in kept] == ["PREVIOUS OUTPUT"]


def test_successful_redact_then_restore_after_recovery_path(tmp_path):
    src, out, m = _fixture(tmp_path)
    assert _redact(src, m, out) == 0
    back = tmp_path / "back.txt"
    assert main(["restore", str(out), "--map", str(m), "-o", str(back)]) == 0
    assert back.read_text() == "alice@example.com"


