---
change: CHG-0001-adopt-specsync-5-0-1-and-trust-1-0-0-governance-for-the-http-fledge-plugin
artifact: testing
---

# Testing

Local acceptance requires `fledge lanes run verify`, strict 100% SpecSync coverage, all four integrations, a healthy Trust doctor, and a clean diff. The native lane must retain the full 58-test security suite.

## Requirement Evidence

- `REQ-http-001`: `SSRFGuardTests` covers unsafe IPv4/IPv6 classes, mapped addresses, public addresses, and default/explicit private access behavior.
- `REQ-http-002`: `RequestBuilderTests` covers allowed methods, rejected methods and schemes; the release build preserves the no-redirect dispatcher contract.
- `REQ-http-003`: `RequestBuilderTests` and `RedactionTests` cover injection rejection and credential scrubbing.
- `REQ-http-004`: `RequestBuilderTests` covers JSON precedence and content type; `TruncationTests` covers the 64 KB and UTF-8 boundaries.

Hosted acceptance requires the new macOS `trust` job, existing Swift matrix, executable SSRF smoke, and independent Atlas workflow to remain functional.
