# Security policy

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

Please report security issues **privately**, using GitHub's "Report a vulnerability"
button on this repository (Security → Advisories). Do not open a public issue for a
vulnerability.

Include what you found, how to reproduce it, and what you think the impact is. You
should get an acknowledgement within 7 days.

## What counts as a vulnerability here

- A way to make `check` exit `0` on a report it did not evaluate: damaged or partly read
  frontmatter, a declared conflict or finding that is silently skipped, or a missing or
  unreadable file. The core promise is that it gives no verdict on evidence it could not see.
- A way to make `restore` emit a partially restored document, or to make `redact`
  write a map that cannot restore its own output byte for byte.
- Code execution or object construction from report frontmatter. Frontmatter is
  untrusted input. It is parsed only with a `SafeLoader` subclass (`yaml.safe_load` plus a
  duplicate-key check).
- Crashes or catastrophic regex backtracking on crafted input of a reasonable size.

## What does not

- **Wording that evades the lint.** A judgment phrased to avoid the patterns, or a
  5W1H cue word used without a real answer, is a known limit of a pattern-based
  linter, and the README says so. New *shapes* are welcome as ordinary issues or
  pull requests; please include a benign counterexample so the false-positive cost
  can be measured.
- **Personal data the redaction patterns do not cover** (names, street addresses,
  card numbers). That is a documented scope limit. Proposals for new kinds are
  welcome as ordinary pull requests.
