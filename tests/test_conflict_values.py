"""A conflict value written as a date or a number is kept as the text the analyst wrote (YAML
would otherwise hand the checker a date or an int and the conflict read as malformed); a yes/no
value, which YAML turns into a boolean, is still refused. Found writing a case study whose
sources disagreed on a publication date."""
import pytest
from cti_report_lint import conflicts


def side(value):
    return {"source": "s", "value": value, "trust_score": 3}


@pytest.mark.parametrize("value, text", [
    (__import__("datetime").date(2025, 7, 8), "2025-07-08"), (317, "317"), (0.5, "0.5"),
    ("1916faa", "1916faa"),
])
def test_dates_and_numbers_are_kept_as_text(value, text):
    c = conflicts.from_dict({"ctype": "VALUE_MISMATCH", "subject": "x", "a": side(value), "b": side("y")})
    assert c.a.value == text


@pytest.mark.parametrize("value", [True, False, None, ["a"]])
def test_booleans_and_other_shapes_are_still_malformed(value):
    with pytest.raises(TypeError):
        conflicts.from_dict({"ctype": "VALUE_MISMATCH", "subject": "x", "a": side(value), "b": side("y")})
