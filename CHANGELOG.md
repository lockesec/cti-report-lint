# Changelog

## 0.1.0 (2026-10-19)

First public release. What it does:

- **`check`** runs six checks on one Markdown report: judgment lint (ICD 203 likelihood
  bands, no hedged ranges, no bare percentages, no absolute language), 5W1H coverage
  (who, what, when, where, why, how), finding grades, the likelihood ceiling, the conflict
  block, and identifiers. Every judgment issue is
  reported where it occurs, with its line (`--json` adds the column).
- **The ceiling reads the prose.** A band term (or its ICD 203 synonym) in the body that is
  stronger than the strongest graded finding allows is an issue. Negated, quoted, attributed
  and scale-describing terms are skipped, and a term split by a line wrap is still read.
- **A plain report with no findings** lists each likelihood judgment in its prose as "needs
  evidence", with its line. `skeleton` prints a findings block to start from (one finding per
  judgment, at the weakest grade) and writes nothing.
- **Conflicts a person can close.** A conflict can record a decision
  (`resolved_by: {by, winner: a|b|neither, note}`), which clears the block and keeps both
  sides on record.
- **Declared sources.** With `sources:` (id, reliability A-F, optional `derived_from`),
  `confirmed_by` cites ids, corroboration is counted by independent root, and trust 4-5
  needs two independent sources, so circular reporting cannot raise a ceiling. Without
  `sources:`, nothing changes.
- **Identifier checks.** Malformed CVE ids are always flagged. With `--attack-json`,
  unknown, revoked (with its replacement), deprecated and wrongly named ATT&CK technique
  ids are flagged. With `--kev-json`, an exploited-in-the-wild claim for a CVE the CISA KEV
  catalog does not list, with no source cited, is flagged. Without the files the ids are
  reported NOT CHECKED. No reference data is bundled.
- **`redact` / `restore`** replace emails, IPv6 and IPv4 addresses, IBANs, Bitcoin
  addresses, phone numbers and URLs with numbered placeholders and put them back with a
  byte-exact round trip. `redact` restores its own output in memory first and writes nothing
  if the bytes differ. Invisible format and bidi characters inside a value do not hide it.
- **Strict YAML.** Duplicate keys are refused at every level.
- **Adoption ratchet.** `--findings-required-from DATE` lets reports dated before DATE pass
  without findings, marked as grandfathered.
- **Examples** include before and after incident reports, a pre-commit hook, `examples/demo.sh`,
  and `examples/check_readme.py`, which CI uses to hold the README transcript to the demo.

The case studies at <https://github.com/lockesec/case-studies> exposed several rules:
a conflict value written as a date or number is kept as text, "certainly" and "definitely"
with no band are absolute language, and "95% confident" is a bare percentage. How the tool
was hardened, review by review, is in [DESIGN.md](DESIGN.md).
