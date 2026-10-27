<h1 align="center">cti-report-lint</h1>

<p align="center"><b>A linter for threat-intelligence reports</b><br>It fails a report that claims more than its evidence supports</p>

cti-report-lint reads a threat-intelligence report in Markdown and blocks it when the wording outruns the proof.

It is for analysts and security teams who publish incident notes or threat briefings. A careful reviewer catches "90% confidence" or "almost certain" resting on one forum post; this tool flags them mechanically, before the report ships. A second command takes personal data out of a report so it can be shared, and puts it back byte for byte.

It runs offline, with no model calls, so it fits a pre-commit hook or CI.

## Quick start

Python 3.9+, one dependency (PyYAML):

    pip install git+https://github.com/lockesec/cti-report-lint
    cti-report-lint check report.md

The example reports are not in the package. To run the demo, clone the repo:

    git clone https://github.com/lockesec/cti-report-lint && cd cti-report-lint
    pip install . && sh examples/demo.sh

The demo checks a draft report, then the same incident written up properly (CI checks this block against the real output):

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

Each line names one problem and where it is. `judgment:` is wording in the prose, `coverage:` a gap in who, what, when, where, why or how (5W1H), `findings[0]:` a finding worded above its evidence, `conflicts[0]:` two sources that disagree. The reports are [before](examples/incident-report-before.md) and [after](examples/incident-report-after.md); [docs/usage.md](docs/usage.md#the-demo-reports) walks through the fixes.

## How it works

The rules come from two published standards. ICD 203 is the US intelligence community's guide to likelihood wording: seven fixed terms ("band terms"), from "almost no chance" to "almost certain". The Admiralty system grades each source for reliability, A to F. This tool also grades each claim for trust, 1 to 5.

| Command | What it does |
|---|---|
| `check report.md` | Runs six checks, prints each issue with its line number, exits 1 if any fails. `--json` gives the same result as data |
| `skeleton report.md` | Prints a starter `findings:` block, one finding per judgment, at the weakest grade. Writes nothing |
| `redact report.md --map m.json -o out.md` | Replaces emails, IP addresses, phone numbers, IBANs, Bitcoin addresses and URLs with numbered placeholders |
| `restore out.md --map m.json -o back.md` | Puts the originals back byte for byte, or refuses |

Plain prose gets the wording and 5W1H checks. Evidence declared in YAML frontmatter (each finding's type, trust, source reliability, confirmations and likelihood; conflicts with both sides graded) switches on the rest. A report with no `findings:` is blocked; `--findings-required-from DATE` grandfathers an existing archive. Format and options: [docs/usage.md](docs/usage.md#declaring-evidence).

## The checks

A report is blocked if any of six checks fails: judgment wording, 5W1H coverage, finding grades, likelihood ceiling, open conflicts, and identifiers (CVE and ATT&CK ids). The ceiling: trust 5 may say "almost certain", 4 "very likely", 3 "likely", 2 "roughly even chance"; trust 1 or a CONTESTED finding permits no single judgment. The full table, the bands, the strength formula and the conflict severity rule: [docs/rules.md](docs/rules.md).

## Why you can trust it

1. **Exit 2 means it could not look.** A missing, unreadable or non-UTF-8 report exits 2 (NOT EVALUABLE), never 0. Damaged frontmatter blocks the report with the reason; it does not read as "no evidence declared". A finding written as `{}` is blocked, not skipped.
2. **Frontmatter cannot erase a block.** YAML is parsed only through a `SafeLoader` subclass that refuses duplicate keys at every level, so a later `conflicts: []` cannot overwrite an earlier open conflict. A test pins the loader.
3. **Redaction checks itself before writing.** `redact` restores its own output in memory and compares it byte for byte to the input; on a mismatch it writes nothing and exits 2. The round trip is byte-exact, including CRLF and CR line endings. `restore` refuses a placeholder the map lacks or one from another map. The map is plain JSON, mode 0600.
4. **Indicators survive.** IBANs must pass mod-97, Bitcoin addresses their base58check or bech32 checksum, IPv6 candidates Python's `ipaddress`. ISO dates and `CVE-`/`CWE-`/`GHSA-` ids stay in clear. Defanged indicators (`192[.]0[.]2[.]1`) are left alone on purpose. Details and a round-trip transcript: [docs/redaction.md](docs/redaction.md).
5. **The tables are pinned to their sources.** The seven bands, the evidence ceiling, the strength weights and the conflict severity rule each have a test holding them to the cited table.
6. **Offline and deterministic.** Regular expressions and tables; no model calls, no network. `check` is deterministic; the only randomness in `redact` is the nonce on a new map. Detection runs in linear time; tests bound 64 KB adversarial inputs.
7. **The README is held to the tool.** CI runs `examples/demo.sh` and `examples/check_readme.py`, which fails if the quick-start block differs from the demo's output.

## Exit codes

| code | meaning |
|---|---|
| 0 | `check`: passes every check. `redact` / `restore`: done |
| 1 | `check`: **blocked**, each issue printed with its reason. `restore`: refused (a placeholder the map lacks, or one from another map). `redact`: refused (the input already carries this map's placeholders) |
| 2 | **NOT EVALUABLE**: a report, input or map is missing, a directory, not valid UTF-8, unreadable or malformed, or an output could not be written; also `redact` when its output would not restore byte-exact ("redaction would not restore byte-exact; nothing written"). Never a pass, and not a block either |
| 64 | usage error, including input, map and output naming the same file |

## Known limits

- **Cue words are not comprehension.** 5W1H counts a dimension as answered when a cue word appears, so a report can game it.
- **A person's decision is recorded, not checked.** A conflict with `resolved_by` stops blocking on the word of whoever is named.
- **English only.** The judgment heuristics are regular expressions. The prose ceiling compares each band term with the strongest declared finding, so a strong judgment resting on a weak finding passes when another finding is strong.
- **Redaction is pattern-based.** No names, street addresses or card detector (a card number may be caught as a phone number). Some analytic numbers (epoch timestamps, version strings) are over-redacted. The round trip stays exact.
- **One report per `check`.** Loop in the shell for many; see [examples/pre-commit](examples/pre-commit) and [examples/pre-commit-config.yaml](examples/pre-commit-config.yaml).

Every limit, with the exact shapes each rule does and does not match: [docs/known-limits.md](docs/known-limits.md).

## What's different

[cti-expert] states these rules as guidance for an analyst or a model, and MISP's `estimative-language` and `admiralty-scale` taxonomies carry the same vocabulary as tags. This project adds the executable gate: the rules as checks with exit codes, a parser that blocks on damaged evidence instead of reading it as absent, and a reversible redaction that verifies its own round trip. It is a CTI-specific tool, not a general prose linter or PII scrubber.

[lockesec/case-studies](https://github.com/lockesec/case-studies) runs it on write-ups of two real attacks on AI coding agents; some rules in the [changelog](CHANGELOG.md) came from gaps those drafts exposed.

## Credits

It began as a check inside a private AI-experimentation environment and was extracted as a standalone tool. The maintainer designed and directed it. Much of the code was written with AI coding agents, and separate AI sessions reviewed it adversarially; the tests and [DESIGN.md](DESIGN.md) show what was checked.

- **[cti-expert]** by Hieu Ngo (chongluadao.vn), MIT License: the finding types and strength formula, the conflict types and severity rule, the analytic-language rules and evidence ceiling, the 5W1H overlay, and the `[KIND_N]` placeholder scheme. Some expressions in `redact.py` are copied verbatim. MIT notice: [NOTICE](NOTICE).
- **ICD 203** (US ODNI) and Sherman Kent's *Words of Estimative Probability*: the seven likelihood bands. **The Admiralty system:** the A-F source-reliability letters.
- **[MISP taxonomies]** (CC0): used to cross-check the tables.

What was adapted from whom, in detail: [docs/credits.md](docs/credits.md). Attribution corrections are welcome.

## Docs

- [docs/usage.md](docs/usage.md): commands, options, declaring evidence, the demo reports
- [docs/rules.md](docs/rules.md): the checks, likelihood bands, ceiling, strength, conflict severity
- [docs/redaction.md](docs/redaction.md): a round trip, what is redacted, placeholders, the map
- [docs/known-limits.md](docs/known-limits.md): the full list of what it does not catch
- [docs/credits.md](docs/credits.md): what was adapted from whom
- [DESIGN.md](DESIGN.md): why it exists, the design contract, and what independent reviews found

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

[cti-expert]: https://github.com/7onez/cti-expert
[MISP taxonomies]: https://github.com/MISP/misp-taxonomies
