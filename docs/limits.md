# Limits

## How well it works

Measured 2026-11-01 on 34 public threat reports from 13 publishers, read by an agent that labeled sentences without seeing this tool. A second agent on a different model then labeled the same 525 sentences, with no sight of the first labels or the tool. Publishers were split by a fixed hash before any result was read; two wording fixes were made using 6 publishers only, and the other 7 were then read once. Report text and labels are not in this repository, so this cannot be rerun from a clone.

| Sentences, held-out publishers | Flagged before the fixes | Flagged after |
|---|---|---|
| Strong judgment with no evidence nearby (7) | 2 | 6 |
| Strong judgment with evidence nearby (10) | 3 | 7 |
| Credited to someone else (11): should stay quiet | 1 | 2 |
| Plain factual sentence (134): should stay quiet | 4 | 5 |
| Weaker judgment (53): listed by design | 16 | 19 |

What this does and does not show:
- **It finds judgments; it does not judge them.** On a plain report it flags supported and unsupported claims alike, as "needs evidence". Telling them apart takes a declared finding.
- **A flag is counted per line,** so another term on the same line can count as a hit.
- **The gain is mostly confidence wording,** read only as "needs evidence". After the sealed read, the ceiling treatment of those words changed on review; the table was recounted and did not move, but that recount is no longer sealed.
- **Two labelers, 17 strong sentences.** Over all 525 sentences they agreed on which were strong judgments (32 of 34 marked by either; kappa 0.97), and both give 13 of 17 held out. They agreed less on whether a claim was supported (24 of the 32; kappa 0.55 on "unsupported", 0.78 on "supported"), and the table's "no evidence" row is 5 of 5 under the second labeler and 4 of 4 where both agree. Read these as a size, not a rate.
- **Both labelers saw only the sentences the first one picked out,** by a keyword scan and by hand, so a judgment it missed is not counted. Both are AI models, so they may share blind spots.
- **Not measured.** Bare percentages and hedged ranges appeared in none of the 34 reports. Two "absolute" sentences were both missed; both labels were arguable. No report had findings declared, so the ceiling and conflict checks have no real-world measurement.
- **The selection is convenience:** mostly vendor write-ups on state-linked actors from 2023-2026.

## Known holes

What the checks do not catch. The README lists the ones that matter most.

- **Confidence has no ceiling.** Likelihood terms are held to a finding's evidence; "high confidence" is only asked for evidence. A high-confidence claim on a weak finding passes. "We attribute the delay to patching" is listed though it names no actor.
- **Sentence edges are approximate.** "e.g." ends a sentence, and a list item after "reports that" loses that cover, so it is flagged.
- **A named author reads as someone else.** "Example Security attributes the activity to" is treated as crediting a source; only "we attribute" reads as the author's own. A confidence word in such a sentence goes unread.
- **Cue words are not comprehension.** 5W1H counts a dimension as answered when a
  cue word appears ("actor", "sector", "vector", a `YYYY-MM` date). A report can
  game it, and relative dates such as "last month" do not count as *when*.
- **A person's decision is recorded, not checked.** A CRITICAL, HIGH or NOTABLE conflict
  clears when `resolved_by` names who decided, which side won (or neither) and why; the tool
  cannot judge the decision, only require that it is complete and keep both sides on record.
- **No ceiling is printed where no likelihood is allowed.** For trust 1 and CONTESTED
  findings no single judgment is permitted, so a finding-level issue shows the ceiling as
  `None` and a prose issue says 'no single judgment'. (A `likelihood:` value outside the seven band terms is not a limit: it
  blocks, with the term named.)
- **Evidence grades are the author's word.** Without a `sources:` block, `trust_score`,
  `source_reliability` and `confirmed_by` are not cross-checked against each other (trust 5,
  reliability F and an empty `confirmed_by` can pass), repeated entries in `confirmed_by` count
  as repeated confirmations, and a `date:` the author wrote is believed when a ratchet date
  is set. Declare `sources:` to have corroboration counted by independent root.
- **Only some phrasings count as a band term or as exploited in the wild.** The ceiling reads
  the seven ICD 203 terms and their listed synonyms in Latin letters; "certain" alone and
  fullwidth `％` are not read; Cyrillic and Greek look-alike letters are. The KEV check reads a
  list of phrasings ("actively exploited", "exploited in the wild", "weaponized", ...), only for a
  CVE in the same clause, and treats any
  "no", "not", "never", "without" or "nor" earlier in the clause as negating the claim, so "No
  patch exists and CVE-... is actively exploited in the wild" is not flagged. An attribution
  cue ("per", "telemetry", "reports") anywhere in a sentence attributes all of it.
- **No reference file, no identifier check, but the verdict is still PASS.** Without
  `--attack-json` or `--kev-json` those rules cannot run; the result says NOT CHECKED (and
  `--json` carries `identifiers.<kind>.checked: false`) but `verified_ok` and the exit code do
  not change. Read `identifiers` before trusting a pass, or pass `--require-references` to get
  exit 2 unless both files are given.
- **An uncited likelihood term is read only against the strongest finding.** Give a finding an
  `id` and cite it in the sentence as `[id]`, and the term is held to that finding's ceiling.
  Without a citation, a strong judgment resting on a weak finding passes when another finding is
  strong; the output counts such terms, and `--require-citations` blocks them. The tool checks that
  a citation exists and which ceiling applies, not that the finding supports the sentence.
- **English only**, and the judgment-sentence heuristics are regular expressions: an
  attributed statistic phrased without an attribution cue ("reports", "according
  to", "per", "telemetry", ...) is treated as the author's own judgment. The report
  referring to itself ("in this report") is not a cue.
- **Scale wording and look-alikes can add findings.** A report that describes the likelihood scale
  in other words can be flagged, so phrase it as "the likelihood scale" or "band terms". Reading
  Cyrillic and Greek look-alike letters can also add findings.
- **Some spans take their neighbours.** `user=john@example.com` is one span, so `user=` goes with it,
  and a CJK-adjacent run of 8 or more digit characters can read as a phone number.
- **Redaction is pattern-based.** It validates IBAN and Bitcoin checksums but does
  not cover names, street addresses, other wallets, bare domains or hashes (the last
  two are indicators, not personal data). There is no card-number detector: a card
  number such as `4111 1111 1111 1111` may be redacted as a phone number, but nothing
  checks that it is a card, so do not rely on it. It still over-redacts some
  analytic numbers as phone numbers or IPv4 addresses: epoch timestamps, runs of port
  numbers, and four-part version strings such as `10.0.19041.1234`. The round trip
  stays exact, but those values read as placeholders in the redacted copy. Its
  literal-string keying gives one address written two ways two placeholders; that is
  what makes restore byte-exact.
- **Trailing punctuation stays out of a URL.** A final `.`, `,`, `;`, `:`, `!`, `?`, `*` or `_`
  is read as sentence punctuation or Markdown, so a query value that ends in `!` or `_` leaves
  that last character in clear. A phone number run into an extension keeps `x123` in clear.
- **Defanged addresses stay in clear.** `192[.]0[.]2[.]1`, `192.0.2[.]1`,
  `john(at)example.com` and `john [at] example.com` are not matched, because in CTI
  they are usually indicators written to be shared, so redacting them would be wrong
  as often as right. Part of a half-defanged address can still be caught by another
  pattern. An email with a quoted local part (`"john doe"@example.com`) is not
  matched either. If the defanged form is personal data in your report, redact it by
  hand.
- **Email is matched by shape.** An address with a dotted domain, or with an IPv4 or
  `IPv6:` address literal as its domain (`john@[192.0.2.1]`), is redacted whole.
  `x@localhost` and `john@example` (no dot) are not redacted, since a dotless host
  cannot be told from ordinary text such as a handle.
- **Non-standard address literals keep the local part in clear.** An unclosed
  `john@[IPv6:...`, `john@[IPv6:fe80::1%eth0]` (a zone id is not valid inside an
  address literal), `john@[192.0.2.1:25]` and `john@[::1]` are not matched as an
  email, so `john@` stays in the redacted copy; only the address inside may be
  redacted by its own pattern.
- **Over-redaction of hex-only names.** A name made only of hex digits and `::`
  (`a::b`, `fade::cafe`, `dead::beef`) is a valid IPv6 address, so C++ scope names
  like these are redacted as IPV6. The round trip stays exact. Also see the phone,
  epoch and version-string over-redactions above.
- **Windows interface names with spaces or braces.** In `fe80::1%Ethernet 2` the
  address and `%Ethernet` are redacted and ` 2` stays in clear; in `fe80::1%{GUID}`
  the address is redacted and `%{GUID}` stays. A zone id is read as letters, digits,
  and `.`/`-` joins only.
- **Spaces or hyphens only, for IBAN groups.** A compact IBAN, or one in groups of
  four joined consistently by spaces or by hyphens, is redacted; groups joined by
  any other character, or by a mix, are not.
- **Some honest negations still block.** The absolute-language rule recognizes
  "not", "never" and "n't" (straight or curly apostrophe) directly before the word.
  "can't be guaranteed", "not-guaranteed" and "not at all guaranteed" still block;
  reword them ("is not guaranteed").
- **Only some URL schemes are redacted.** `http(s)`, `ftp`, `sftp`, defanged
  `hxxp(s)` and `www.` forms are; `ftps://`, `file://` and `ssh://` are not. A
  username or host inside one is left in clear unless another pattern (an email, an
  IPv4 address) catches part of it.
- **"Impossible travel" is exempt, other uses of "impossible" are not.** It is the
  standard name of an identity-alert type, not a likelihood claim, so the absolute
  language rule skips that exact phrase (also hyphenated). Every other use of
  "impossible" still blocks.
- **One report per `check`.** Loop in the shell for many (see `examples/pre-commit`).
