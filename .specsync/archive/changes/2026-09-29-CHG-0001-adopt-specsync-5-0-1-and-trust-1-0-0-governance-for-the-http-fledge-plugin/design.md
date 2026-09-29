---
change: CHG-0001-adopt-specsync-5-0-1-and-trust-1-0-0-governance-for-the-http-fledge-plugin
artifact: design
---

# Design

Adopt the existing stable HTTP spec into SpecSync 5.0.1 at 100% coverage and install all integrations.

Trust runs a release build, all Swift tests, and manifest capability validation through Fledge on macOS 15. Risk blocks, provenance is progressive, and Trust-managed Atlas stays disabled because the repository already publishes coverage independently. The workflow pins Trust 1.0.0 immutably.
