"""cti-report-lint: lint incident and threat-intelligence reports for
evidence-honest language (ICD 203 likelihood terms, likelihood capped at the
evidence grade, open source conflicts, 5W1H coverage), and redact personal data
reversibly. Runtime dependency: PyYAML, loaded only through a ``SafeLoader`` subclass."""
from __future__ import annotations

__version__ = "0.1.0"

from .validate import validate_report  # noqa: E402

# The redaction functions live in cti_report_lint.redact. They are not
# re-exported here, because a package attribute named `redact` would shadow
# the submodule of the same name.
__all__ = ["__version__", "validate_report"]
