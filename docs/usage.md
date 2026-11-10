# Usage

How to run the commands and declare evidence. The checks themselves are in [rules.md](rules.md).

```console
# Lint one report (Markdown, optionally with YAML frontmatter):
cti-report-lint check report.md
cti-report-lint check report.md --json

# Take personal data out, and put it back:
cti-report-lint redact report.md --map report.map.json -o report.redacted.md
cti-report-lint restore report.redacted.md --map report.map.json -o report.md
```

## Installing

Python 3.11+, one runtime dependency (PyYAML). On a system Python marked "externally managed" (PEP 668), `pip install` refuses outside a virtual environment: run `python3 -m venv .venv && . .venv/bin/activate` first, or use `pipx install .`.

`check` options:

| Option | Default | Meaning |
|---|---|---|
| `--min-5w1h N` | 4 | How many of who/what/when/where/why/how the body must answer |
| `--findings-required-from DATE` | off | Adoption ratchet, see below |
| `--json` | | Machine-readable result on stdout; `verified_ok` is `true` exactly when the report passes (exit 0), and `issues` lists what blocked it |
| `--attack-json FILE` | off | MITRE ATT&CK STIX bundle; checks technique ids |
| `--kev-json FILE` | off | CISA KEV catalog; checks exploited-in-the-wild claims |
| `--require-references` | off | Exit 2 unless both files above are given |
| `--require-citations` | off | Block a likelihood term in the prose that cites no finding as `[id]` |

## Declaring evidence

Plain prose gets the judgment lint and the 5W1H check. Evidence goes in the
frontmatter, and switches on the other three checks:

```yaml
---
date: 2026-09-21
findings:
  - finding_type: PRIMARY        # PRIMARY | DERIVED | CONFIRMED | CONTESTED | ANECDOTAL
    trust_score: 4               # 1-5: how good is the CLAIM
    source_reliability: B        # A-F: how good is the SOURCE
    confirmed_by: [EDR process tree, proxy logs]
    likelihood: very likely      # optional, one of the seven band terms
conflicts:
  - ctype: VALUE_MISMATCH        # VALUE_MISMATCH | TIME_IMPOSSIBLE | EXISTENCE_DISPUTE
    subject: initial access vector
    a: {source: EDR telemetry, value: phishing attachment, trust_score: 5}
    b: {source: customer IT, value: exposed RDP, trust_score: 2}
---
```

**Declared sources and circular reporting.** Declare each source once and cite it by id:

```yaml
sources:
  - {id: edr, reliability: A}
  - {id: vendor-feed, reliability: B}
  - {id: vendor-blog, reliability: C, derived_from: vendor-feed}
findings:
  - {finding_type: PRIMARY, trust_score: 4, source_reliability: B,
     confirmed_by: [edr, vendor-blog]}
```

`derived_from` names the source a source repeats. Corroboration is counted by root. Follow
`derived_from` until you reach a source that repeats nothing; citations that reach the same root
count once, so a blog restating a feed is not a second confirmation. With `sources:` declared, every
`confirmed_by` entry must be a declared id, trust 4 or 5 needs at least two independent
sources, the confirmation bonus in the strength score uses the independent count, and an
unknown `derived_from` or a cycle blocks. The tool never grades a source; it checks that what
you declared is consistent. Without `sources:`, `confirmed_by` stays free text. It is optional today: a finding with no `confirmed_by` key passes the field check.

**Technique and CVE ids.** Nothing is bundled: a stale copy would read as current. Download the
references you want checked and pass them:

```console
$ cti-report-lint check report.md --attack-json enterprise-attack.json --kev-json known_exploited_vulnerabilities.json
```

`enterprise-attack.json` is MITRE's STIX bundle (the attack-stix-data repository);
`known_exploited_vulnerabilities.json` is CISA's KEV feed. Every message names the ATT&CK
version or the KEV catalog version it was checked against. An id written as `T1059.001
Command and Scripting Interpreter: PowerShell` (the parent's name first) is a correct citation.
Without a file, the ids are counted and printed as `NOTE: N ... NOT CHECKED`, and `--json`
carries `identifiers.attack.checked: false`. `--require-references` makes that case exit 2 (NOT
EVALUABLE) instead of a pass.

A clause that negates the claim ("no evidence CVE-X is exploited in the wild", "is not known to be
exploited") makes none. Clauses are split at `;`, and a negation anywhere before the claim phrase in
a clause counts, so "patched or not, CVE-X is exploited in the wild" is skipped too. A file that
cannot be read or is not the expected format is NOT EVALUABLE (exit 2). Malformed CVE ids (fewer than four sequence digits, a year
before 1999) are checked without any file.

**Starting from a plain report.** A report with no findings lists each likelihood judgment in
its prose as `needs evidence: '<term>' at line N`. `cti-report-lint skeleton report.md` prints a
`findings:` block with one finding per judgment, each at the weakest grade (ANECDOTAL, trust 1,
reliability F, nothing confirming it), so the report keeps blocking until you grade the real
evidence. It never writes the report. For a report with no frontmatter it prints a whole block
fenced with `---` lines to put at the top; for a report that already has frontmatter it prints
only the `findings:` lines, to paste between its `---` lines.

**A conflict a person has decided.** A CRITICAL, HIGH or NOTABLE conflict needs a human. Record
the decision on the conflict and it stops blocking; both sides stay on record:

```yaml
    resolved_by: {by: tier-2 lead, winner: a, note: firewall export shows RDP closed since 2026-06}
```

`winner` is `a`, `b` or `neither`; `by` and `note` must not be empty (an incomplete decision is
a malformed conflict, which blocks). `check` prints the decision, and `--json` carries
`decided_by`, `winner` and `decision_note` on the conflict.

**A report with no `findings:` is blocked by default**, because the evidence checks
would otherwise evaluate nothing and the report would pass on its prose alone. If you
are adopting the tool on an existing archive, `--findings-required-from 2026-10-01`
lets reports dated before that day omit findings. They pass, with a printed
`GRANDFATHERED` note, and `findings_grandfathered: true` in the JSON so a sweep can
count the backlog. The date comes from `scan_date` or `date` in the frontmatter, then
from a `YYYY-MM-DD` in the file name. An undated report is treated as new.

## Exit codes

`check`:

| Code | Meaning |
|---|---|
| 0 | The report passes every check |
| 1 | **Blocked.** At least one issue; each is printed with its reason |
| 2 | **Not evaluable.** The report is missing, a directory, not valid UTF-8, or unreadable, or `--require-references` was given without both reference files. Never a pass, and not a block either |
| 64 | Usage error |

`redact` and `restore`:

| Code | Meaning |
|---|---|
| 0 | Done |
| 1 | Refused. `restore` found a placeholder the map does not hold, or one from another map, or `redact` was given text that already carries this map's placeholders |
| 2 | An input or map is missing, unreadable or malformed (including a map with a duplicate key), or an output could not be written, or the `redact` output would not restore byte-exact. In that last case nothing is changed or written, and the message is "redaction would not restore byte-exact; nothing written" |
| 64 | Usage error, including input, map and output naming the same file or hard links to one file |

## The demo reports

`examples/incident-report-before.md` is a synthetic managed detection and response (MDR) incident note for a
fictional customer, Example Corp. It blocks on seven issues; the first `check` in the README quick start prints them.
`examples/incident-report-after.md` is the same incident written up properly:

- one band term per judgment, with confidence stated separately
  ("very likely ... (moderate confidence: a single EDR alert chain ...)");
- no invented percentage, and "impossible" replaced by "very unlikely" with the reason;
- the finding re-graded to PRIMARY / trust 4 with its corroboration listed, so
  "very likely" is within its ceiling;
- the conflict settled by evidence: a firewall export contradicted the customer's
  statement, which was re-graded to trust 2, so the conflict is MINOR and
  auto-resolves (the losing side stays on record);
- one line each for who, what, when, where, why and how.

```console
$ cti-report-lint check examples/incident-report-after.md
examples/incident-report-after.md: PASS  (5W1H 6/6, 2 graded finding(s), 1 conflict(s))
  finding[0] PRIMARY strength 9.6 likelihood 'very likely'
  finding[1] DERIVED strength 5.7 likelihood 'likely'
$ echo $?
0
$ cti-report-lint redact examples/incident-report-before.md --map map.json -o red.md
redacted 4 span(s) (4 new); map -> map.json
```

`examples/pre-commit` (a plain git hook) and `examples/pre-commit-config.yaml` (for
the pre-commit framework) run `check` on staged reports.
