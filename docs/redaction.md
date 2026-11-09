# Redaction

A round trip on the before report (run from `examples/`):

```console
$ cti-report-lint redact incident-report-before.md --map map.json -o red.md
redacted 4 span(s) (4 new); map -> map.json
$ grep -n 'EXC-WS-22 (' red.md
19:At 13:47 UTC the EDR agent on EXC-WS-22 ([IPV4_1#1591d1]) raised an alert for an
$ cti-report-lint restore red.md --map map.json -o back.md && cmp incident-report-before.md back.md && echo same
same
```

The nonce after `#` is new for each map, so yours will differ.

`redact` covers email, IPv6, IPv4, IBAN, Bitcoin addresses, phone numbers and
URLs. Each span becomes a numbered placeholder such as `[EMAIL_1#3fa9c2]`. The six
hex digits are the map's nonce, chosen so they do not already occur in the text, so
text that only looks like a placeholder is never mistaken for one. Spans are found
against the original text in one pass (a URL that holds an email address is one
span), and restore is a single non-recursive pass, so every redact/restore round
trip is byte-exact, including CRLF and CR line endings. The map is plain JSON, written atomically with mode 0600 because
it holds every original value; a restored output file gets the same mode. Seeding
the same map across files keeps numbering consistent (writers on one map serialize on a `.<map>.lock` file beside it). Values are found next to
Markdown emphasis (`_x_`, `*x*`, `` `x` ``), brackets, `key:` and `key=` prefixes and
through invisible characters (next section). IPv6 candidates are confirmed by Python's `ipaddress`
(including `[IPv6:...]` address literals, zone IDs and `::`-terminated prefixes such
as `2001:db8::/32`), so clock times and MAC addresses survive; a bare `::` in prose is left alone.
A name made only of hex digits and `::` (`a::b`, `fade::cafe`) is a valid IPv6
address and is redacted as one, which round-trips but over-redacts C++ code. IBANs (compact, or in groups of four separated by spaces or by hyphens, any case) must pass the
mod-97 check, and Bitcoin addresses their base58check or bech32/bech32m checksum, so
hashes are not taken for accounts or wallets. URLs cover `http(s)`, `ftp`, `sftp`,
defanged `hxxp(s)` (any case) and `www.` forms. ISO and DD.MM.YYYY dates and
`CVE-`, `CWE-`, `CAPEC-`, `GHSA-`, `OSV-`, `EDB-ID-` and `KB` identifiers are left
in clear and never hide a phone number next to them.

What it leaves in clear, on purpose or by limit: defanged addresses (`192[.]0[.]2[.]1`,
`192.0.2[.]1`, `john(at)example.com`, `john [at] example.com`), which in CTI are
usually indicators meant to be shared, emails with a quoted local part, `x@localhost` and `john@example` (no dot), and URLs with the schemes `ftps://`, `file://` and `ssh://`. An email whose domain is an address literal (`john@[192.0.2.1]`, `john@[IPv6:2001:db8::1]`) is redacted whole. There is
no card-number detector; a card number written as `4111 1111 1111 1111` may be
redacted as a PHONE span, and other layouts may pass through. See
[limits.md](limits.md). Placeholder-shaped text already
in a report is itself redacted, so `restore` can refuse to emit anything if the text
holds a placeholder the map lacks or one from another map. Detection runs in linear
time; the tests bound 64 KB adversarial inputs.

## Invisible characters

Detection ignores characters that render as nothing, so `bob@exam<U+00AD>ple.com`
is still one email; restore puts every one back where it was. Handled:

- every Unicode format character (category Cf) that is invisible: soft hyphen
  U+00AD, Arabic letter mark U+061C, Mongolian vowel separator U+180E,
  U+200B-200F (zero-width space, joiners, left/right marks), U+202A-202E (bidi
  embeddings and overrides), U+2060-2064 (word joiner and invisible operators),
  U+2066-206F (bidi isolates and deprecated shaping controls), U+FEFF,
  U+FFF9-FFFB, U+13430-1343F, U+1BCA0-1BCA3, U+1D173-1D17A, U+E0001 and the tag
  characters U+E0020-E007F;
- U+034F combining grapheme joiner;
- variation selectors U+FE00-FE0F and U+E0100-E01EF, and the Mongolian free
  variation selectors U+180B-180D.

Not handled, because they print a visible sign: U+0600-0605, U+06DD, U+070F,
U+0890-0891, U+08E2, U+110BD and U+110CD. Other invisible-looking characters that
are letters or spaces (Hangul fillers U+115F/U+1160/U+3164/U+FFA0, U+2800 braille
blank, U+3000 and the other space separators) are not removed either.

## Round-trip self-check

Before writing anything, `redact` restores its own output in memory with the new
map and compares it byte for byte to the input. On any mismatch (or an internal overlapping-span error) it writes nothing
and exits 2 with "redaction would not restore byte-exact; nothing written".

## Address literals

Non-standard address literals keep the local part in clear: an unclosed
`john@[IPv6:...`, `john@[IPv6:fe80::1%eth0]`, `john@[192.0.2.1:25]` and
`john@[::1]` leave `john@` in the redacted copy. See `limits.md`.
