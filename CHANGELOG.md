# Changelog

## 0.2.0 (unreleased)

Two rules change what blocks. Both were found by running synthetic probe reports against 0.1.1.

- **The ceiling is two-sided.** It limited only how HIGH a likelihood term could go, so "almost
  no chance" on one trust-2 anecdote passed where "almost certain" blocked. The bands are
  symmetric about even chance, and the ceiling now limits the distance from it in either
  direction, in a finding's `likelihood:` and in the prose ("unlikely", "highly improbable"
  and the other low terms are read; "remote" still is not). A report that states a strong
  negative over weak evidence now blocks.
- **Trust 4-5 needs two confirming sources, with or without a `sources:` block.** Before, the
  rule bound only a report that declared its sources: trust 5 with `confirmed_by: []` passed,
  and the same claim was blocked once its sources were written down. Without the block the
  entries are counted as claimed (distinct, non-empty) and the report says `independence NOT
  CHECKED` (`independence_not_checked` in `--json`). New flag `--require-sources` blocks that
  case instead.
- A finding-level ceiling issue for trust 1 or CONTESTED names 'no single judgment' instead
  of `None`.
- The "after" example declares its sources.

## 0.1.1 (2026-11-09)

- Python 3.11 or newer is required (3.9 and 3.10 are end-of-life). CI tests 3.11 to 3.14 on `ubuntu-latest`.
- **Author.** The package metadata and NOTICE name the author, locke.
- **Fewer false blocks.** "Make sure 50%", "certain hosts", "risk assessment" and "an
  estimated 30%" are no longer read as the author's judgment; "we are 90% sure" still is.
  A plain `source:` frontmatter key is no longer taken for a misspelt `sources`.
- **Plainer messages.** An open conflict "blocks the report until resolved"; absolute
  language is "no evidence supports certainty". `--json`'s `verified_ok` is documented.
- **Tests.** The linear-time tests compare two input sizes instead of a wall-clock bound.

## 0.1.0 (2026-11-09)

First public release, Apache-2.0. How the tool was hardened: [DESIGN.md](DESIGN.md).

- **`check`** runs six checks on one Markdown report: judgment wording, 5W1H coverage, finding grades, the likelihood ceiling, open conflicts and identifiers. Every judgment issue is reported with its line, and `--json` adds the column.
- **The ceiling reads the prose.** A band term stronger than the strongest graded finding allows is an issue. Negated, quoted and attributed terms are skipped.
- **A sentence can cite its finding.** Give a finding an `id` and write `[id]` in the sentence: its likelihood term is then held to that finding's ceiling. Uncited terms are counted, and `--require-citations` blocks them.
- **Confidence wording counts.** "High confidence", "moderate confidence" and "we attribute" need evidence, because real reports word their strongest claims that way. They have no ceiling. Measured on real reports: [docs/limits.md](docs/limits.md).
- **A plain report with no findings** lists each likelihood judgment as "needs evidence", with its line. `skeleton` prints a findings block to start from and writes nothing.
- **Conflicts a person can close.** `resolved_by` clears the block and keeps both sides on record.
- **Declared sources.** With `sources:`, corroboration is counted by independent root, so circular reporting cannot raise a ceiling.
- **Identifier checks.** Malformed CVE ids are always flagged. `--attack-json` checks ATT&CK technique ids and `--kev-json` checks exploited-in-the-wild claims. Without the files the ids are reported NOT CHECKED, and `--require-references` makes that exit 2. No reference data is bundled.
- **Strict frontmatter.** Duplicate keys are refused at every level, and misspelled keys block and name the key to use. Frontmatter that opens below line 1 blocks instead of reading as "no evidence".
- **`redact` and `restore`** replace emails, IP addresses, IBANs, Bitcoin addresses, phone numbers and URLs with numbered placeholders and put them back byte for byte. `redact` checks its own round trip and writes nothing if it fails.
- **`--findings-required-from DATE`** lets reports dated before DATE pass without findings, marked as grandfathered.
- **Examples:** before and after incident reports, a pre-commit hook, and a demo that CI holds the README to.
