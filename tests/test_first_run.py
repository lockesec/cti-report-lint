"""A useful first run on a plain report (no frontmatter): each likelihood judgment in the prose is
listed with its line as needing evidence, and `skeleton` prints a frontmatter block to start
from (it never writes the report). And a conflict a person has decided: `resolved_by` with who,
which side, and why clears the block and keeps both sides on record."""
import json
from pathlib import Path

import pytest
import yaml
from cti_report_lint import cli
from cti_report_lint.conflicts import from_dict
from cti_report_lint.validate import validate_report

PLAIN = ("# Phishing wave\n\nOn 2026-10-02 the actor sent invoice lures to finance.\n"
         "It is almost certain the group behind it is FIN7.\nThe loader is likely Carbanak.\n")


def test_a_plain_report_lists_each_judgment_as_needing_evidence(tmp_path):
    p = tmp_path / "plain.md"
    p.write_text(PLAIN)
    issues = validate_report(p)["issues"]
    need = [i for i in issues if i.startswith("needs evidence:")]
    assert any("'almost certain' at line 4" in i for i in need)
    assert any("'likely' at line 5" in i for i in need)
    assert not any("would evaluate NOTHING" in i for i in issues)


def test_skeleton_prints_one_finding_per_judgment_and_writes_nothing(tmp_path, capsys):
    p = tmp_path / "plain.md"
    p.write_text(PLAIN)
    assert cli.main(["skeleton", str(p)]) == 0
    out = capsys.readouterr().out
    assert p.read_text() == PLAIN
    fm = yaml.safe_load(out.split("---")[1])
    assert [f["likelihood"] for f in fm["findings"]] == ["almost certain", "likely"]
    assert all(set(f) >= {"finding_type", "trust_score", "source_reliability", "confirmed_by"}
               for f in fm["findings"])


def test_skeleton_on_a_report_with_findings_says_so(tmp_path, capsys):
    p = Path(__file__).resolve().parents[1] / "examples" / "incident-report-after.md"
    assert cli.main(["skeleton", str(p)]) == 1
    assert "already declares" in capsys.readouterr().err


CONFLICT = {"ctype": "VALUE_MISMATCH", "subject": "initial access vector",
            "a": {"source": "EDR telemetry", "value": "phishing", "trust_score": 5},
            "b": {"source": "customer IT", "value": "exposed RDP", "trust_score": 4}}


def test_a_human_decision_resolves_a_critical_conflict_and_keeps_both_sides():
    c = from_dict(dict(CONFLICT, resolved_by={"by": "tier-2 lead", "winner": "a",
                                              "note": "firewall export shows RDP closed"}))
    assert c.severity == "CRITICAL" and not c.is_open() and c.resolution == "HUMAN_RESOLVED"
    assert c.winner == "EDR telemetry" and c.b.source == "customer IT"


@pytest.mark.parametrize("rb", [{"by": "", "winner": "a", "note": "x"},
                                {"by": "lead", "winner": "c", "note": "x"},
                                {"by": "lead", "winner": "a", "note": ""},
                                "lead"])
def test_an_incomplete_decision_is_malformed(rb):
    with pytest.raises((ValueError, TypeError)):
        from_dict(dict(CONFLICT, resolved_by=rb))


def test_a_resolved_conflict_does_not_block_and_is_printed(tmp_path, capsys):
    src = (Path(__file__).resolve().parents[1] / "examples" / "incident-report-after.md").read_text()
    fm_end = src.index("\n---", 3)
    fm = yaml.safe_load(src[3:fm_end])
    fm["conflicts"] = [dict(CONFLICT, resolved_by={"by": "tier-2 lead", "winner": "neither",
                                                   "note": "both partly right; see timeline"})]
    p = tmp_path / "r.md"
    p.write_text("---\n" + yaml.safe_dump(fm, sort_keys=False) + src[fm_end:])
    res = validate_report(p)
    assert res["verified_ok"], res["issues"]
    assert cli.main(["check", str(p)]) == 0
    assert "resolved by tier-2 lead" in capsys.readouterr().out


def test_skeleton_for_a_report_with_frontmatter_prints_lines_to_merge(tmp_path, capsys):
    p = tmp_path / "r.md"
    p.write_text("---\ndate: 2026-09-21\n---\nIt is almost certain the actor returns.\n")
    assert cli.main(["skeleton", str(p)]) == 0
    out = capsys.readouterr().out
    assert "---" not in out
    merged = "---\ndate: 2026-09-21\n" + out + "---\nIt is almost certain the actor returns.\n"
    fm = yaml.safe_load(merged.split("---")[1])
    assert fm["date"] and fm["findings"][0]["likelihood"] == "almost certain"


def test_skeleton_for_a_plain_report_still_prints_a_fenced_block(tmp_path, capsys):
    p = tmp_path / "plain.md"
    p.write_text("It is likely the actor returns.\n")
    cli.main(["skeleton", str(p)])
    out = capsys.readouterr().out
    assert out.startswith("---\n") and json.dumps(yaml.safe_load(out.split("---")[1])["findings"])
