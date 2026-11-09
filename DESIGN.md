# Design: why cti-report-lint works the way it does

## Starting point

The tool began as a check inside a private experiment and was extracted as a
standalone package. It is an independent Python implementation of
rules from published analytic standards and from cti-expert (credited in
[docs/credits.md](docs/credits.md) and [NOTICE](NOTICE)).

## Why it exists

Security reports get acted on: a managed detection and response (MDR) note decides whether a customer rebuilds a
host, a threat briefing decides what gets patched first. They fail in a few
predictable ways that a reviewer only catches on a careful day:

- **Vague or falsely precise odds.** "It is likely to very likely that..." straddles
  two bands. "We assess with 90% confidence" invents a number nobody measured.
  "This is impossible" claims more than the evidence can.
- **Certainty that outruns the evidence.** "Almost certain", resting on one
  unverified forum post.
- **Contradictions that disappear.** Two sources disagree, and the report quietly
  picks one.
- **Effort instead of answers.** "Scanned 40 feeds" and no word on who, what, how
  or why.
- **Personal data in a document that travels further than planned.**

The standards for this already exist (ICD 203 estimative language, Admiralty source
grading). What was missing is a mechanical check a writer can run before sending a
report, or in CI.

## Design contract

1. **Never report a verdict on evidence it could not see.** A missing report exits 2.
   Damaged frontmatter blocks the report; it does not read as "no evidence declared".
2. **Offline and deterministic.** Regular expressions and tables; no model calls.
3. **One runtime dependency,** PyYAML, loaded only through a `SafeLoader` subclass
   (a test pins that). Duplicate YAML keys are refused at every level, so a later key cannot
   erase an earlier blocking one.
4. **Redaction must round-trip byte for byte,** or refuse. Spans are found on the
   original text in one pass, and restore is a single non-recursive pass.

## What independent reviews found

Separate AI sessions that had not written the code reviewed it adversarially. Each finding was
reproduced against the source and pinned to a test before it was fixed. Later findings supersede
earlier ones.

| Area | What it found |
|---|---|
| Redaction round trip and frontmatter | Redaction was not reliably reversible (nested spans, placeholder collisions). `findings: [{}]` passed. A duplicate YAML key could erase a blocking `conflicts:` block. Compressed IPv6 (`2001:db8::1`) was not redacted. |
| Scoring and file permissions | Unknown likelihood terms passed (rank -1). Conflict-side trust scores outside 1-5 auto-resolved. Source reliability used substring membership, so `AB` and the empty string were accepted. The map inherited the process umask (0664) though it holds every original value. Impossible calendar dates were accepted. |
| Trailing IPv6, CRLF and hard links | Trailing-compression IPv6 (`2001:db8::`, `fe80::`) leaked. CLI restore was not byte-exact for CRLF input. A hard link to the input bypassed the alias check and overwrote the original. An impossible ratchet date (for example 2026-99-99) was accepted. |
| IPv6 zone ids and the restore self-check | An IPv6 zone id swallowed the first group of a following address (`fe80::1%eth0-2001:db8::1`), so the output did not restore byte-exact. Fixed in two layers: the zone grammar stops before a `:` or further alphanumerics, and `redact` now restores its own output in memory and refuses to write on any mismatch (exit 2). |
| Overlapping spans and absolutes | Overlapping spans were possible between kinds; they are now resolved per kind and asserted away. Per cent was taken for an attribution; hard-wrapped, negated and curly-apostrophe absolutes; address-literal emails. |
| Invisible characters and IBANs | Invisible format and bidi characters (soft hyphen, marks, isolates, variation selectors) hid values from redaction; the set is widened and documented. A hyphen-grouped IBAN left its country code in clear. The internal overlap assertion could surface as a traceback; it now exits 2 like the self-check. Windows interface names with spaces or braces and hex-only C++ names are documented as limits. |

Each finding was fixed with a regression test before publication. According to the
author, every defect that was reproduced was also present in the private original,
which was fixed in turn; that is the author's statement, not something this
repository can show. Used on the author's own notes, the strict loader found two with duplicate
keys that had silently dropped their first values.

## Deliberate non-goals

- **No comprehension of the report.** The 5W1H check counts cue words.
- **No judgment of a person's decision.** A conflict closed with `resolved_by` is recorded
  and keeps both sides, but the tool cannot tell whether the decision was right. See
  [docs/limits.md](docs/limits.md).
- **No names, street addresses or card numbers in redaction.**
