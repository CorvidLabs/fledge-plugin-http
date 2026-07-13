## ADDED

### REQUIREMENT REQ-http-001

The plugin SHALL reject every resolved private, loopback, link-local, multicast, broadcast, unspecified, metadata, and IPv4-mapped unsafe target before opening a socket unless the caller explicitly enables private access.

Acceptance Criteria
- The SSRF test suite rejects each unsafe IPv4 and IPv6 class.
- Public addresses remain accepted and `allow_private` is false by default.

### REQUIREMENT REQ-http-002

The plugin SHALL allow only HTTP and HTTPS requests using GET, POST, PUT, PATCH, or DELETE and SHALL not follow redirects.

Acceptance Criteria
- Unsupported schemes and methods are rejected before dispatch.
- Redirect responses are returned without automatic follow-up requests.

### REQUIREMENT REQ-http-003

The plugin SHALL validate header names and values and redact authorization material from surfaced errors.

Acceptance Criteria
- CR, LF, NUL, empty, and colon-bearing header names or values are rejected as applicable.
- Bearer and basic credentials do not appear in returned diagnostics.

### REQUIREMENT REQ-http-004

The plugin SHALL prefer validated JSON input over raw body input and return a structured, size-bounded response envelope.

Acceptance Criteria
- JSON input sets the content type unless explicitly supplied and takes precedence over raw body.
- Response bodies are capped at 64 KB on a valid UTF-8 boundary and report truncation.
