# cti-report-lint

**Checks that a threat-intelligence report claims only what its evidence supports, and fails it if not. A second command redacts personal data and restores it byte for byte.**

`check` reads a report in Markdown and blocks it when the wording outruns the proof: a hedged "likely to very likely", a "90% confidence" nobody measured, a finding called "almost certain" on one unverified forum post, two sources that contradict each other while the report quietly picks one, or a timeline with no who or how. `redact` swaps emails, IP addresses, phone numbers, IBANs, Bitcoin addresses and URLs for numbered placeholders so a report can be shared. `restore` puts the original back exactly, or refuses.

Both run offline with no model calls. They fit a pre-commit hook or CI as easily as a terminal. The rules read the words and the declared evidence, not who wrote them.

The rules come from two published standards. ICD 203 is the US intelligence community's guide to estimative language: seven fixed likelihood terms, from "almost no chance" to "almost certain". The Admiralty system grades each source for reliability, A to F. This tool also grades each claim for trust, 1 to 5.

## Quick start

    pip install git+https://github.com/sethpsonnier/cti-report-lint

The example reports are not in the pip package, so clone the repo to run the demo:

    git clone https://github.com/sethpsonnier/cti-report-lint && cd cti-report-lint
    pip install . && sh examples/demo.sh

This is what the demo prints for the two example reports (CI checks the block against the real output):

```console
$ cti-report-lint check incident-report-before.md
incident-report-before.md: BLOCKED  (5W1H 2/6, 1 graded finding(s), 1 conflict(s))
  judgment: bare percentage (false precision — use a band term) at line 21: '90%'
  judgment: hedged likelihood range (use ONE term per judgment) at line 21: 'likely to very likely'
  judgment: 0/100 or absolute language (OSINT cannot establish) at line 22: 'impossible'
  coverage: 5W1H only 2/6 (missing when, where, why, how)
  findings[0]: likelihood 'almost certain' exceeds evidence ceiling 'roughly even chance' (ANECDOTAL/trust2)
  judgment: 'very likely' at line 21 exceeds the strongest evidence ceiling among the declared findings ('roughly even chance')
  conflicts[0]: OPEN CRITICAL VALUE_MISMATCH on 'initial access vector' — blocks VERIFIED
  finding[0] ANECDOTAL strength 2.8 likelihood 'almost certain'
(exit 1)
$ cti-report-lint check incident-report-after.md
incident-report-after.md: PASS  (5W1H 6/6, 2 graded finding(s), 1 conflict(s))
  finding[0] PRIMARY strength 9.6 likelihood 'very likely'
  finding[1] DERIVED strength 5.7 likelihood 'likely'
(exit 0)
```

Each line names what it found. `judgment:` is a wording problem in the prose. `coverage:` is a gap in who, what, when, where, why or how. `findings[0]:` is a declared finding worded above its evidence. `conflicts[0]:` is a disagreement between sources. `finding[0]` is the summary of a graded finding, with its strength score.

The reports are [examples/incident-report-before.md](examples/incident-report-before.md) and [examples/incident-report-after.md](examples/incident-report-after.md); the diff between them is the walk-through below. The demo also runs a redact and restore round trip and compares the result to the original. Python 3.9+, one runtime dependency (PyYAML). On a system Python marked "externally managed" (PEP 668), see [docs/usage.md](docs/usage.md#installing).

## What a run looks like

1. **Write the report in Markdown.** Evidence goes in YAML frontmatter: each finding's type, trust score (1-5), source reliability (A-F), what confirmed it, and the likelihood you want to state. Contradictions between sources go in the same block, as conflicts with both sides graded.
2. **Run `check`.** It prints a verdict and each issue with its reason, and a line number where the issue sits in the prose. The first command above blocks a draft on seven: three judgment problems, a 5W1H gap (fewer than four of who, what, when, where, why, how answered), a declared likelihood over its evidence ceiling, a band term in the prose stronger than any finding supports, and an open CRITICAL conflict. A band term is one of the seven ICD 203 likelihood phrases.
3. **Fix what it names.** One band term per judgment, confidence stated separately; the invented percentage gone; the finding re-graded with its corroboration listed, so "very likely" is within its ceiling; the conflict settled by evidence (a firewall export contradicted the customer, whose side was re-graded to trust 2, so the conflict auto-resolves and stays on record); one line each for who, what, when, where, why and how.
4. **PASS.** The second command above is the same incident written up that way. `--json` gives the same result as data for a dashboard or a sweep.
5. **Share it safely.** `redact` writes a private map; `restore` uses it.

## Declaring evidence

Plain prose gets the judgment lint and the 5W1H check. The frontmatter switches
on the evidence checks:

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

A report with no `findings:` is blocked, because the evidence checks would be
grading nothing. Adopting the tool on an existing archive?
`--findings-required-from 2026-10-01` lets reports dated before that day pass
with a printed `GRANDFATHERED` note and `findings_grandfathered: true` in the
JSON, so the backlog stays countable. Every option, and how the date is read:
[docs/usage.md](docs/usage.md).

## The checks

A report is blocked if any of six checks fails: judgment wording, 5W1H coverage, finding grades, likelihood ceiling, open conflicts, and identifiers. The ceiling: trust 5 may say "almost certain", 4 "very likely", 3 "likely", 2 "roughly even chance", and trust 1 or a CONTESTED finding permits no single judgment. The full table, the likelihood bands, the strength formula and the conflict severity rule: [docs/rules.md](docs/rules.md).

## Redaction

```console
$ cti-report-lint redact incident-report-before.md --map map.json -o red.md
redacted 4 span(s) (4 new); map -> map.json
$ grep -n 'EXC-WS-22 (' red.md
19:At 13:47 UTC the EDR agent on EXC-WS-22 ([IPV4_1#1591d1]) raised an alert for an
$ cti-report-lint restore red.md --map map.json -o back.md && cmp incident-report-before.md back.md && echo same
same
```

The six hex digits after `#` are the map's nonce, chosen afresh for each new
map (yours will differ) so that text which merely looks like a placeholder is
never mistaken for one. The map is plain JSON (placeholder to original value),
written with mode 0600. Seed the same map across several files to keep the
numbering consistent. What is matched, what is left in clear on purpose (defanged
indicators such as `192[.]0[.]2[.]1`, since in CTI they are usually meant to be
shared), and how invisible characters are handled: [docs/redaction.md](docs/redaction.md).

## Why you can trust it

- **It says when it could not look.** A missing, unreadable or non-UTF-8 report
  exits 2 (NOT EVALUABLE: the tool could not look), never 0. Frontmatter that is present but damaged
  blocks the report with the reason, instead of reading as "no evidence
  declared". A report whose only finding is `{}` is blocked, not skipped.
- **Nothing in the frontmatter can erase a block.** YAML is parsed only through
  a `SafeLoader` subclass that also refuses duplicate keys at every level, so a
  later `conflicts: []` cannot overwrite an earlier open conflict; a test pins
  the loader.
- **Redaction checks itself before writing.** `redact` restores its own output
  in memory and compares it byte for byte to the input; on any mismatch it
  writes nothing and exits 2. Spans are found on the original text in one pass
  and restore is a single non-recursive pass, so the round trip is byte-exact
  including CRLF and CR line endings. `restore` refuses a placeholder the map
  lacks or one from another map, rather than emitting a half-restored document.
- **Indicators survive.** IBANs must pass mod-97 and Bitcoin addresses their
  base58check or bech32 checksum, IPv6 candidates are confirmed by Python's
  `ipaddress`, and ISO dates and `CVE-`/`CWE-`/`GHSA-` identifiers are kept in
  clear, so hashes, dates and vulnerability ids are not taken for accounts,
  wallets or phone numbers.
- **The tables are pinned to their sources.** The seven bands (ICD 203), the
  evidence ceiling, the strength weights and the conflict severity rule each
  have a test that holds them to the cited table.
- **Offline.** Regular expressions and a few tables; no model calls, no
  network. `check` is deterministic; the only randomness in `redact` is the
  nonce on a new map. Detection runs in linear time, and the tests bound 64 KB
  adversarial inputs.
- **The README is held to the tool.** CI runs `examples/demo.sh` and
  `examples/check_readme.py`, which fails if the quick-start block above
  differs from what the demo prints.

## Exit codes

NOT EVALUABLE (exit 2): it could not check, so it will not call the result clean.

| code | meaning |
|---|---|
| 0 | `check`: passes every check. `redact` / `restore`: done |
| 1 | `check`: **blocked**, each issue printed with its reason. `restore`: refused (a placeholder the map lacks, or one from another map). `redact`: refused (the input already carries this map's placeholders) |
| 2 | **NOT EVALUABLE**: a report, input or map is missing, a directory, not valid UTF-8, unreadable or malformed, or an output could not be written; also `redact` when its output would not restore byte-exact ("redaction would not restore byte-exact; nothing written"). Never a pass, and not a block either |
| 64 | usage error, including input, map and output naming the same file |

## Known limits

- **Cue words are not comprehension.** 5W1H counts a dimension as answered when a cue word appears, so a report can game it.
- **A person's decision is recorded, not checked.** A conflict with `resolved_by` stops blocking on the word of whoever is named; the tool cannot tell whether the decision was right.
- **English only;** the judgment heuristics are regular expressions. The prose ceiling compares each band term with the STRONGEST declared finding, so a strong judgment resting on a weak finding passes when another finding is strong.
- **Redaction is pattern-based.** No names, street addresses or card detector (a card number may be caught as a phone number). Some analytic numbers (epoch timestamps, version strings) are over-redacted. The round trip stays exact.

One report per `check`; loop in the shell for many (see [examples/pre-commit](examples/pre-commit) and [examples/pre-commit-config.yaml](examples/pre-commit-config.yaml)). The full list, with the exact shapes each rule does and does not match: [docs/known-limits.md](docs/known-limits.md).

## See it used

[sethpsonnier/case-studies](https://github.com/sethpsonnier/case-studies) holds write-ups of two real attacks on AI coding agents. Both run this linter on their own reports, and some of the rules in the [changelog](CHANGELOG.md) were added because those drafts exposed gaps.

## Prior art and credits

It began as a check inside a private AI-experimentation environment and was extracted as a standalone tool. The maintainer designed and directed it. Much of the code was written with AI coding agents, and separate AI sessions reviewed it adversarially; the tests and [DESIGN.md](DESIGN.md) show what was checked.

The standards are ICD 203 for estimative language and the Admiralty system for source grading; MISP's `estimative-language` and `admiralty-scale` taxonomies carry the same vocabulary as tags. cti-expert states these rules as guidance for an analyst or a model. What this project adds is the executable gate: the rules as checks with exit codes, a parser that blocks on damaged evidence rather than reading it as absent, and a reversible redaction that verifies its own round trip. It is a CTI-specific tool, not a general prose linter or a general PII scrubber.

Ideas it borrows:

- **[cti-expert]** by Hieu Ngo (chongluadao.vn), MIT License: the finding types and strength formula, the conflict types and severity rule, the analytic-language rules and evidence ceiling, the 5W1H overlay, and the `[KIND_N]` placeholder scheme. Some expressions in `redact.py` are copied verbatim. MIT notice: [NOTICE](NOTICE).
- **ICD 203** (US ODNI) and Sherman Kent's *Words of Estimative Probability*: the seven likelihood bands. **The Admiralty system:** the A-F source-reliability letters.
- **[MISP taxonomies]** (CC0): used to cross-check the tables.

Attribution corrections are welcome.

## Docs

- [docs/usage.md](docs/usage.md) - commands, options, declaring evidence, the demo reports
- [docs/rules.md](docs/rules.md) - the checks, likelihood bands, ceiling, strength, conflict severity
- [docs/redaction.md](docs/redaction.md) - what is redacted, placeholders, the map
- [docs/known-limits.md](docs/known-limits.md) - the full list of what it does not catch
- [docs/credits.md](docs/credits.md) - what was adapted from whom
- [DESIGN.md](DESIGN.md) - why it exists, the design contract, and what independent reviews found

## License

Apache-2.0 - see [LICENSE](LICENSE) and [NOTICE](NOTICE).

[cti-expert]: https://github.com/7onez/cti-expert
[MISP taxonomies]: https://github.com/MISP/misp-taxonomies
