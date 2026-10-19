# Credits

**Original to this project:** the executable report gate and its exit codes, the
judgment-sentence scoping of the percentage rule, the 5W1H cue detector,
damage-aware frontmatter parsing, the open-conflict-blocks-the-report binding,
fail-loud restore, the date and identifier KEEP pass and checksum validation in
redaction, and the test suite.

Developed in a private AI-experimentation environment and extracted as a standalone
tool. It builds on published research and open-source work, credited below. If you
believe your work influenced this project and isn't credited, please open an issue.
Attribution corrections are always welcome.

- **[cti-expert]** by Hieu Ngo (chongluadao.vn), MIT License. The MIT notice is
  reproduced in [NOTICE](../NOTICE).
  - *Adapted* from `engine/finding-framework.md`: the five finding types and their
    base weights, the 1-5 trust scale kept separate from A-F source reliability, the
    strength formula and its +1.5 confirmation cap.
  - *Adapted* from `engine/conflict-resolver.md`: the three conflict types used here
    (of its five), the four severity levels, the `grade_severity` rule, and the idea
    that an open contradiction keeps a claim from verified confidence.
  - *Adapted* from `handbook/analytic-standards.md`: the language rules (never 0 or
    100, one term per judgment, no bare percentages, likelihood kept apart from
    confidence), the evidence ceiling table, and the 5W1H "effort versus answer"
    overlay.
  - *Adapted* from `scripts/redact.py`: the numbered `[KIND_N]` placeholder scheme
    with one map per run and literal-string keying.
  - *Copied verbatim* from `scripts/redact.py`: the IPv4 octet expression and the two
    Bitcoin address alternatives; the boundaries around them, and the checksum
    validation, are ours. (Earlier versions also copied its longest-first restore
    loop; it was replaced by a single-pass restore after nested spans failed to
    round-trip.)

  cti-expert expresses these rules as guidance for an analyst or a model; this tool
  is an independent Python implementation of them. Where it deliberately differs
  (fail-loud restore, judgment-scoped percentages, the gate and its exit codes), the
  difference is ours, and so are any mistakes.
- **ICD 203, *Analytic Standards*** (US ODNI) and Sherman Kent's *Words of Estimative
  Probability* (CIA, 1964): the seven likelihood bands and the separation of
  likelihood from confidence (*inspired by*).
- **The Admiralty (NATO) source-grading system:** the A-F source-reliability letters.
  The Admiralty code pairs them with a 1-6 credibility scale; this tool uses
  cti-expert's 1-5 trust score instead, so the pair is not the Admiralty code itself.
- Richards J. Heuer Jr., *Psychology of Intelligence Analysis* (CIA, 1999), and the
  UNODC *Criminal Intelligence Manual for Analysts* (2011): the tradecraft lineage
  cti-expert names for these rules (*inspired by*).
- **[MISP taxonomies]** (CC0), `estimative-language` and `admiralty-scale`: used to
  cross-check the tables.

[cti-expert]: https://github.com/7onez/cti-expert
[MISP taxonomies]: https://github.com/MISP/misp-taxonomies
