---
date: 2026-09-21
findings:
  - finding_type: PRIMARY
    trust_score: 4
    source_reliability: B
    confirmed_by: [EDR process tree, proxy logs]
    likelihood: very likely
  - finding_type: DERIVED
    trust_score: 3
    source_reliability: C
    confirmed_by: [shared loader hash]
    likelihood: likely
conflicts:
  - ctype: VALUE_MISMATCH
    subject: initial access vector
    a: {source: EDR telemetry, value: phishing attachment, trust_score: 5}
    b: {source: customer IT, value: exposed RDP, trust_score: 2}
    note: >-
      Firewall configuration export shows RDP closed at the perimeter since
      2026-06; the customer statement was re-graded to trust 2.
---
# Incident 0142: ransomware staging on EXC-WS-22

Customer: Example Corp. Analyst on shift: tier-2 MDR.

**What.** An encoded PowerShell command on EXC-WS-22 (192.0.2.44) fetched a
loader from 198.51.100.23. We assess this was very likely ransomware staging
(moderate confidence: a single EDR alert chain, confirmed by the process tree
and proxy logs).

**When.** First seen 2026-09-20 13:47 UTC; the host was isolated at
14:02 UTC, so dwell time was 15 minutes.

**Where.** One finance workstation; no other hosts in the customer's
infrastructure contacted 198.51.100.23.

**Who.** The loader hash matches the one used by the actor in incident 0131.
Attribution to the same group is likely (low confidence: one shared artifact).

**Why.** The staging pattern matches earlier financially motivated
intrusions against the same sector.

**How.** Initial access vector: a phishing attachment opened at 13:45 UTC.
The customer's report of exposed RDP was checked and is not supported (see
the conflict entry). Lateral movement is very unlikely: the host was isolated
before any internal connection attempt.

Customer contact for follow-up: jane.doe@example.com.
