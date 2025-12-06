# Five Helix QPPI Firewall

A lineage-safe, digital-only firewall modeling five concurrent “helices”:
1. Data Integrity (DNA)
2. Runtime Safety (RNA)
3. Audit & Reflection
4. Guardian Oversight (Authorship & Consent)
5. Joy & Ceremony (Humor & Non-punitiveness)

This reference implementation is intended for sandboxed, non-weapon systems with guardian-controlled authorship and explicit consent seals.

## Features
- Declarative policy definitions (JSON-like dicts)
- Engine-enforced rate limits, cooldowns, context locks
- Signed audit events (HMAC)
- Guardian consent and real-time pause/revoke
- Joy strand enforcing calm, non-punitive UX constraints
- CLI for local runs

## Quick start
```bash
pip install -e .
qppi-firewall --help
qppi-firewall apply --profile child_a --policy examples/policy_min.json
qppi-firewall start-session --profile child_a --context Learning
qppi-firewall stop-all
