# The rules

| # | Check | Blocks when | Source |
|---|---|---|---|
| 1 | Judgment lint | A hedged range: two band terms joined by "to", "or", "/" or a hyphen, en dash or em dash ("likely to very likely"); a bare percentage (or "N percent") in a sentence that states the author's own judgment ("we assess", "confidence", "confident", "sure", "probability"); 0%, 100% (also written 100.0%), "impossible", "guaranteed", "absolutely certain", "no chance whatsoever", and a certainty adverb with no band ("certainly", "definitely", "undoubtedly", "without a doubt"; "almost certainly" is the top band and is fine), including when a line wrap or extra spaces fall inside the phrase (a negated "not guaranteed" is fine, and so is the detection name "impossible travel") | ICD 203; rules as written in cti-expert's analytic standards. The judgment-sentence scoping is ours |
| 2 | 5W1H coverage | Fewer than `--min-5w1h` of who/what/when/where/why/how have a cue word in the body | Overlay idea from cti-expert; the cue detector is ours |
| 3 | Finding grades | A finding with only some of the fields, an unknown type, trust outside 1-5, reliability outside A-F, or `confirmed_by` that is not a list | cti-expert's finding framework; A-F letters from the Admiralty code |
| 4 | Likelihood ceiling | A finding's declared likelihood is stronger than its evidence allows, or a band term in the prose (or its ICD 203 synonym: "probable", "highly probable", "nearly certain", ...) is stronger than the strongest declared finding allows; negated, quoted and attributed terms are skipped | cti-expert's ceiling table |
| 5 | Conflict block | Any conflict that is not auto-resolved, or cannot be parsed | cti-expert's conflict resolver; binding it to an exit code is ours |
| 6 | Identifiers | A CVE id is malformed; with `--attack-json` (an ATT&CK STIX bundle you download), a technique id is unknown, revoked (named with its replacement), deprecated, or followed by another technique's name; with `--kev-json` (CISA's KEV catalog), a sentence claims exploitation in the wild for a CVE the catalog does not list and cites no source. Without the files, the ids are counted and printed as NOT CHECKED | Ours |

Plus: frontmatter that is present but unparseable blocks (checks 3-5 cannot run), and
a report without findings blocks (see above).

**Seven likelihood bands** (ICD 203): almost no chance 1-5% · very unlikely 5-20% ·
unlikely 20-45% · roughly even chance 45-55% · likely 55-80% · very likely 80-95% ·
almost certain 95-99%.

**Evidence ceiling.** The trust score sets the strongest term a finding can carry:
5 almost certain, 4 very likely, 3 likely, 2 roughly even chance, 1 no single
judgment. The finding type can only lower it: ANECDOTAL tops out at roughly even
chance, and CONTESTED permits no single judgment at all. A PRIMARY finding with trust
2 is still capped at roughly even chance.

**Finding strength** (reported, not gated) = type base (CONFIRMED 8, PRIMARY 7,
DERIVED 4, ANECDOTAL 2, CONTESTED 0) + 0.4 × trust + 0.5 per confirmation, with the
confirmation bonus capped at 1.5 and the total at 10. CONTESTED is always 0: a
contradicted claim contributes nothing rather than averaging against good evidence.

**Conflict severity**, from both sides' trust: both ≥ 4 CRITICAL; both ≥ 3 and neither
≥ 4 HIGH; one ≥ 4 and the other ≤ 2 MINOR, which auto-resolves to the stronger side;
anything else NOTABLE. Only MINOR auto-resolves. Everything else blocks.
