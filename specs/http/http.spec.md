---
module: http
version: 1
status: stable
files:
  - Sources/FledgeHttp/main.swift
  - Sources/FledgeHttp/Protocol.swift
  - Sources/FledgeHttp/RequestBuilder.swift
  - Sources/FledgeHttp/SSRFGuard.swift
  - Sources/FledgeHttp/Dispatcher.swift
  - Sources/FledgeHttp/Redaction.swift
  - plugin.toml
depends_on: []
---

# http.spec.md - v1

## Purpose

Typed authenticated REST client with SSRF protection. Calls JSON / HTTP APIs for the
agent and returns a structured envelope: status code, response headers, content-type,
body (UTF-8, capped), and elapsed milliseconds. Complements `fledge-plugin-web`, which
scrapes pages to readable text; this plugin is for talking to APIs.

## Files

| Path | Responsibility |
|------|----------------|
| `plugin.toml` | Manifest: metadata and `[[commands]]` block per exposed command |
| `Package.swift` | Swift package: executable target `FledgeHttp`, swift-tools 6.0 |
| `Sources/FledgeHttp/main.swift` | Entry point: init handshake, command dispatch |
| `Sources/FledgeHttp/Protocol.swift` | fledge-v1 JSON-lines types and `PluginIO` |
| `Sources/FledgeHttp/RequestBuilder.swift` | Arg parsing, request preparation, validation |
| `Sources/FledgeHttp/SSRFGuard.swift` | DNS resolution and IP address classification |
| `Sources/FledgeHttp/Dispatcher.swift` | URLSession dispatch, response envelope, body cap |
| `Sources/FledgeHttp/Redaction.swift` | Secret scrubbing from error strings |

## Public API

| Surface | Required args | Optional args | Notes |
|---------|---------------|---------------|-------|
| http-request | url | method, headers, query, body, json, bearer, basic_user, basic_pass, allow_private | Make an authenticated request; return a structured JSON envelope. Method defaults to GET. |
| http-get | url | headers, query, bearer, basic_user, basic_pass, allow_private | Convenience GET. Same envelope and guard as http-request. |
| http-post | url | json, body, headers, query, bearer, basic_user, basic_pass, allow_private | Convenience POST. Prefer json for JSON payloads. |

The response envelope is a pretty-printed JSON object:

| Field | Type | Meaning |
|-------|------|---------|
| status | number | HTTP status code |
| ok | bool | True when status is 2xx |
| content_type | string or null | Response Content-Type, if present |
| headers | object | Response headers as a lowercase string map |
| body | string | Response body, UTF-8 lossy, capped at 64 KB |
| truncated | bool | True when the body was clipped at the cap |
| elapsed_ms | number | Wall-clock milliseconds for the request |

## Invariants

1. The SSRF guard runs before any socket opens. Every resolved A/AAAA record is
   checked, and private / loopback / link-local / multicast / broadcast / unspecified /
   cloud-metadata (`169.254.169.254`) targets are refused. IPv4-mapped IPv6 addresses
   are re-validated as IPv4 so `::ffff:127.0.0.1` cannot slip through.
2. The guard is ON by default. `allow_private=true` is the documented opt-out for
   trusted local services.
3. Redirects are NOT followed; a 3xx to a private address cannot bypass the pre-flight.
4. Only `http` and `https` schemes are allowed.
5. Only GET / POST / PUT / PATCH / DELETE methods are allowed.
6. Authorization material (bearer token, basic password) is never logged and is
   redacted (`<redacted>`) from echoed errors and header validation messages.
7. Header names and values are validated; control characters (CR, LF, NUL) are
   rejected so a header cannot inject extra headers or split the request.
8. The `json` arg, when present, takes precedence over `body`, is validated as JSON,
   and sets `Content-Type: application/json` unless the caller supplied that header.
9. The response body is UTF-8 lossy and capped at 64 KB; truncation sets the
   `truncated` flag and cuts on a UTF-8 char boundary.

## Behavioral Examples

```
Given the agent calls http-get { url: "http://169.254.169.254/latest/meta-data" }
When the SSRF guard runs
Then the request is refused before any socket is opened
And the plugin returns an error naming the blocked IP
```

```
Given the agent calls http-post { url: "https://api.example.com/items", json: "{\"name\":\"x\"}", bearer: "TOKEN" }
When the server returns 201 Created
Then the plugin returns an envelope with status 201, ok true, the response headers, and elapsed_ms
And the Authorization header value is never logged
```

```
Given the agent calls http-get { url: "http://localhost:8080", allow_private: "true" }
When the operator has opted out of the SSRF guard
Then the request is permitted against the loopback service
```

## Error Cases

| Error | When | Behavior |
|-------|------|----------|
| SSRF blocked | URL resolves to private/loopback/link-local/metadata IP and `allow_private` is unset | Refused before fetch, with an override hint |
| Non-HTTP scheme | `file://`, `ftp://`, etc. | Refused with "scheme not allowed" |
| Bad method | Method outside GET/POST/PUT/PATCH/DELETE | Refused with "method not allowed" |
| Invalid JSON body | `json` arg is not parseable JSON | Refused with "invalid json body" |
| Header injection | Header value contains CR / LF / NUL | Refused; secret-bearing values redacted |
| Redirect | Server returns 3xx | Returned as-is in the envelope; not followed |
| Size cap | Body exceeds 64 KB | Truncated; `truncated` flag set true |

## Dependencies

- Foundation (URLSession, JSONSerialization) -- Apple SDK, zero external dependencies

## Change Log

| Version | Date | Changes |
|---------|------|---------|
| 1 | 2026-06-10 | Initial spec. Swift 6 rewrite of the Merlin Rust reference. Binary version `0.1.0`. |
