# Contributing

Thanks for helping. Three rules keep this linter trustworthy.

**1. Every rule change ships with a case it must catch and a negative control.**
Add a test that the new or changed rule must flag, and one that it must stay quiet
on: ordinary report prose that is close to the pattern. The existing pairs are the
model: an attributed vendor statistic is not flagged, but "we assess with 90%
confidence" is; an auto-resolved conflict does not block, but a CRITICAL one does.
In the pull request, say how you checked the false-positive rate: which reports, how
many, how many hits. A linter whose top findings are noise trains people to stop
reading it.

**2. Tables that come from a source stay pinned to that source.**
The likelihood bands (ICD 203), the evidence ceiling, the strength weights and the
conflict severity rule (cti-expert) each have a test that pins them to the cited
table. Changing one of them is a deliberate divergence: update the test, the module
comment and docs/rules.md together, and say why in the pull request.

**3. Credit what you borrow.**
If a contribution adapts someone else's code, table or rule, name the source in the
module's header comment and in the README's Credits section, and make sure its
license allows it. Material under a license that requires a notice goes in `NOTICE`.

All example and test data is invented. Use fictional organizations, RFC 5737 addresses
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `example.com` mail, and
build secret-looking values (wallet addresses, IBANs) from string fragments at
runtime so secret-scanning push protection stays quiet. Each example directory carries a
`SYNTHETIC-DATA` file stating this; keep it, and add one to any new example directory.

Run the tests without installing the package:

```console
python -m pip install pytest pyyaml hypothesis
python -m pytest
```

Without `hypothesis` the property tests in `tests/test_properties.py` are skipped.

PyYAML is the only runtime dependency. It is loaded only through a `SafeLoader` subclass
(the duplicate-key-refusing loader in `_yaml.py`), and that should stay the same.
