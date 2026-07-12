---
change: CHG-0001-adopt-specsync-5-0-1-and-trust-1-0-0-governance-for-the-http-fledge-plugin
artifact: testing
---

# Testing

Local acceptance requires `fledge lanes run verify`, strict 100% SpecSync coverage, all four integrations, a healthy Trust doctor, and a clean diff. The native lane must retain the full 58-test security suite.

Hosted acceptance requires the new macOS `trust` job, existing Swift matrix, executable SSRF smoke, and independent Atlas workflow to remain functional.
