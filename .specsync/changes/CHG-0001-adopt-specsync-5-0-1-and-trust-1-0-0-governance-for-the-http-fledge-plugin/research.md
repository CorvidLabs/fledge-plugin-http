---
change: CHG-0001-adopt-specsync-5-0-1-and-trust-1-0-0-governance-for-the-http-fledge-plugin
artifact: research
---

# Research

All six implementation files are covered by the stable HTTP spec. Existing tests exercise request validation, credential redaction, IPv4/IPv6 SSRF classification, and UTF-8-safe truncation. CI also performs a release build and an executable SSRF smoke.

SpecSync 5 interpreted code-formatted command and envelope names as Swift exports, so the stable spec's presentation was normalized without changing semantics. Standalone Atlas and Pages remain independent.
