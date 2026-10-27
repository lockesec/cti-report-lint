# Known limits

- **Cue words are not comprehension.** 5W1H counts a dimension as answered when a
  cue word appears ("actor", "sector", "vector", a `YYYY-MM` date). A report can
  game it, and relative dates such as "last month" do not count as *when*.
- **A person's decision is recorded, not checked.** A CRITICAL, HIGH or NOTABLE conflict
  clears when `resolved_by` names who decided, which side won (or neither) and why; the tool
  cannot judge the decision, only require that it is complete and keep both sides on record.
- **No ceiling is printed where no likelihood is allowed.** For trust 1 and CONTESTED
  findings no single judgment is permitted, so the issue text shows the ceiling as
  `None`. (A `likelihood:` value outside the seven band terms is not a limit: it
  blocks, with the term named.)
- **English only**, and the judgment-sentence heuristics are regular expressions: an
  attributed statistic phrased without an attribution cue ("reports", "according
  to", "per", "telemetry", ...) is treated as the author's own judgment. The report
  referring to itself ("in this report") is not a cue.
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
