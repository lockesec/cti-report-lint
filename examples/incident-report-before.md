---
date: 2026-09-20
findings:
  - finding_type: ANECDOTAL
    trust_score: 2
    source_reliability: D
    confirmed_by: []
    likelihood: almost certain
conflicts:
  - ctype: VALUE_MISMATCH
    subject: initial access vector
    a: {source: EDR telemetry, value: phishing attachment, trust_score: 4}
    b: {source: customer IT, value: exposed RDP, trust_score: 4}
---
# Incident 0142: suspicious PowerShell on EXC-WS-22

Customer: Example Corp. Analyst on shift: tier-2 MDR.

At 13:47 UTC the EDR agent on EXC-WS-22 (192.0.2.44) raised an alert for an
encoded PowerShell command that reached out to 198.51.100.23. We assess with
90% confidence this was ransomware staging. It is likely to very likely the
actor is the same group as last month. Lateral movement is impossible because
the host was isolated.

The host was isolated at 14:02 UTC. Forensic collection is pending.

Customer contact for follow-up: jane.doe@example.com, +1 (555) 010-4477.
