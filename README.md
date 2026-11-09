<h1 align="center">cti-report-lint</h1>

<p align="center"><b>A linter for threat-intelligence reports</b><br>It fails a report that claims more than its evidence supports</p>

cti-report-lint reads a threat-intelligence report in Markdown and blocks it when the wording outruns the proof.

A careful reviewer catches "90% confidence" or "almost certain" resting on one forum post. This tool catches them mechanically, before the report ships. It is for analysts and security teams who publish incident notes or threat briefings.

A second command, `redact`, takes emails, IP addresses and other personal data out of a report so it can be shared. `restore` puts it back byte for byte.

Designed for:

- **A person or an agent writing a report.** It runs offline with no model calls, on its own, in a
  pre-commit hook or in CI.
- **Evidence declared in the report. The full check needs it.** Plain prose gets only the wording and
  coverage checks, and a report with no findings is blocked.
- **Reference files you download, to check ids.** Without the ATT&CK and KEV files those ids are
  reported NOT CHECKED, and the report can still pass unless you add `--require-references`.

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
  NOTE: 2 likelihood term(s) cite no finding, so they were read only against the strongest one (cite as [id], or --require-citations)
  finding[0] ANECDOTAL strength 2.8 likelihood 'almost certain'
(exit 1)
$ cti-report-lint check incident-report-after.md
incident-report-after.md: PASS  (5W1H 6/6, 2 graded finding(s), 1 conflict(s))
  finding[0] PRIMARY strength 9.6 likelihood 'very likely'
  finding[1] DERIVED strength 5.7 likelihood 'likely'
(exit 0)
```

Each line names one problem and where it is. `judgment:` is wording in the prose, `coverage:` a gap in who, what, when, where, why or how (5W1H), `findings[0]:` a finding worded above its evidence ceiling (the strongest term its trust grade allows), `conflicts[0]:` two sources that disagree. The reports are [before](examples/incident-report-before.md) and [after](examples/incident-report-after.md); [docs/usage.md](docs/usage.md#the-demo-reports) walks through the fixes.

## How it works

The rules come from two published standards. ICD 203 is the US intelligence community's guide to likelihood wording: seven fixed terms ("band terms"), from "almost no chance" to "almost certain". The Admiralty system grades each source for reliability, A to F. This tool also grades each claim for trust, 1 to 5.

| Command | What it does |
|---|---|
| `check report.md` | Runs six checks, prints each issue with its line number, exits 1 if any fails. `--json` gives the same result as data |
| `skeleton report.md` | Prints a starter `findings:` block, one finding per judgment, at the weakest grade. Writes nothing |
| `redact report.md --map m.json -o out.md` | Replaces emails, IP addresses, phone numbers, IBANs, Bitcoin addresses and URLs with numbered placeholders |
| `restore out.md --map m.json -o back.md` | Puts the originals back byte for byte, or refuses |

Plain prose gets the wording and 5W1H checks. Evidence goes in YAML frontmatter and switches on the rest: for each finding its type, trust, source reliability, confirmations and likelihood, and for each conflict a grade on both sides. A report with no `findings:` is blocked; `--findings-required-from DATE` grandfathers an existing archive. Format and options: [docs/usage.md](docs/usage.md#declaring-evidence).

## The checks

A report is blocked if any of six checks fails: judgment wording, 5W1H coverage, finding grades, likelihood ceiling, open conflicts, and identifiers (CVE and ATT&CK ids).

The ceiling: trust 5 may say "almost certain", 4 "very likely", 3 "likely", 2 "roughly even chance". Trust 1 or a CONTESTED finding permits no single judgment.

The full table, the bands, the strength formula and the conflict severity rule: [docs/rules.md](docs/rules.md).

## Why you can trust it

1. **Exit 2 means it could not look.** A missing, unreadable or non-UTF-8 report exits 2 (NOT EVALUABLE), never 0. Damaged frontmatter blocks the report with the reason; it does not read as "no evidence declared". A finding written as `{}` is blocked, not skipped.
2. **Frontmatter cannot erase a block.** YAML is parsed only through a `SafeLoader` subclass that refuses duplicate keys at every level, so a later `conflicts: []` cannot overwrite an earlier open conflict. A test pins the loader.
3. **Redaction checks itself before writing.** `redact` restores its own output in memory and compares it byte for byte to the input; on a mismatch it writes nothing and exits 2. The round trip is byte-exact, including CRLF and CR line endings. `restore` refuses a placeholder the map lacks or one from another map. The map is plain JSON, mode 0600.
4. **Indicators survive.** IBANs must pass mod-97, Bitcoin addresses their base58check or bech32 checksum, IPv6 candidates Python's `ipaddress`. ISO dates and `CVE-`/`CWE-`/`GHSA-` ids stay in clear. Defanged indicators (`192[.]0[.]2[.]1`) are left alone on purpose. Details and a round-trip transcript: [docs/redaction.md](docs/redaction.md).
5. **The tables are pinned to their sources.** The seven bands, the evidence ceiling, the strength weights and the conflict severity rule each have a test holding them to the cited table.
6. **Offline and deterministic.** Regular expressions and tables; no model calls, no network. The only randomness is the nonce `redact` puts on a new map. Detection runs in linear time; tests bound 64 KB adversarial inputs.
7. **The README is held to the tool.** CI runs `examples/demo.sh` and `examples/check_readme.py`, which fails if the quick-start block differs from the demo's output.

## Exit codes

| code | meaning |
|---|---|
| 0 | `check`: passes every check. `redact` / `restore`: done |
| 1 | `check`: **blocked**, each issue printed with its reason. `restore`: refused (a placeholder the map lacks, or one from another map). `redact`: refused (the input already carries this map's placeholders) |
| 2 | **NOT EVALUABLE**. Nothing was checked, so it is never a pass and not a block either. Causes: a report, input or map that is missing, a directory, not valid UTF-8, unreadable or malformed; an output that could not be written; `--require-references` without both reference files; or `redact` output that would not restore byte-exact |
| 64 | usage error, including input, map and output naming the same file |

## Where it falls short

- **It can't tell supported from unsupported in plain prose.** It noticed 13 of 17 strong judgments in reports from publishers held out of tuning, and asks for evidence behind each, whether or not the report gives it.
- **Its rules are wording rules.** A cue word can satisfy 5W1H, and a claim worded another way goes unread. English only.
- **Declared evidence is the author's word.** Grades are checked against each other, not against the world.

How it was measured, known holes and what is untested: [docs/limits.md](docs/limits.md).

## What's different

[cti-expert] states these rules as guidance for an analyst or a model, and MISP's `estimative-language` and `admiralty-scale` taxonomies carry the same vocabulary as tags. This project adds the executable gate: the rules as checks with exit codes, a parser that blocks on damaged evidence instead of reading it as absent, and a reversible redaction that verifies its own round trip. It is a CTI-specific tool, not a general prose linter or PII scrubber.

[lockesec/case-studies](https://github.com/lockesec/case-studies) runs it on write-ups of two real attacks on AI coding agents; some rules came from gaps those drafts exposed: a conflict value written as a date or number is kept as text, "certainly" and "definitely" with no band are absolute language, and "95% confident" is a bare percentage.

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
- [docs/limits.md](docs/limits.md): the full list of what it does not catch
- [docs/credits.md](docs/credits.md): what was adapted from whom
- [DESIGN.md](DESIGN.md): why it exists, the design contract, and what independent reviews found

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

[cti-expert]: https://github.com/7onez/cti-expert
[MISP taxonomies]: https://github.com/MISP/misp-taxonomies
