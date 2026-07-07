# fledge-plugin-http

![spec coverage](https://img.shields.io/endpoint?url=https://corvidlabs.github.io/fledge-plugin-http/badges/coverage.json)

Authenticated HTTP/REST client as a first-class `fledge` plugin, with SSRF guards.
Complements `fledge-plugin-web` (which scrapes pages to text); this plugin is for
calling JSON APIs and returning a structured response envelope.

A plugin for [fledge](https://github.com/CorvidLabs/fledge). Built in Swift 6 using
Foundation's `URLSession`. Zero external dependencies.

## Commands

### `http-request`

Make an authenticated HTTP request and get back a structured JSON envelope.

```
fledge http-request --url https://api.example.com/items
fledge http-request --url https://api.example.com/items --method POST --json '{"name":"x"}'
fledge http-request --url https://api.example.com/me --bearer "$TOKEN"
fledge http-request --url https://api.example.com/report --basic_user alice --basic_pass secret
```

### `http-get`

Convenience GET (method is fixed; all other options apply):

```
fledge http-get --url https://api.example.com/status
fledge http-get --url https://api.example.com/search --query '{"q":"swift"}'
```

### `http-post`

Convenience POST (method is fixed; prefer `json` for JSON payloads):

```
fledge http-post --url https://api.example.com/events --json '{"type":"deploy"}'
fledge http-post --url https://api.example.com/upload --body 'raw text' --headers '{"Content-Type":"text/plain"}'
```

## Response envelope

Every successful call returns a pretty-printed JSON object:

```json
{
  "body": "...",
  "content_type": "application/json",
  "elapsed_ms": 142,
  "headers": { "content-type": "application/json", "x-request-id": "abc" },
  "ok": true,
  "status": 200,
  "truncated": false
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `status` | number | HTTP status code |
| `ok` | bool | True when status is 2xx |
| `content_type` | string or null | Response `Content-Type` header |
| `headers` | object | All response headers (lowercase keys) |
| `body` | string | UTF-8 body, capped at 64 KB |
| `truncated` | bool | True when body was clipped at the cap |
| `elapsed_ms` | number | Total wall-clock time in milliseconds |

## Arguments

| Arg | Commands | Description |
|-----|----------|-------------|
| `url` | all | Required. Absolute URL, `http` or `https` only. |
| `method` | `http-request` | GET (default), POST, PUT, PATCH, DELETE. |
| `headers` | all | JSON object of request headers, e.g. `{"Accept":"application/json"}`. CR/LF/NUL rejected. |
| `query` | all | JSON object of query params appended to the URL. |
| `json` | `http-request`, `http-post` | JSON request body. Validated, sent with `Content-Type: application/json`. Takes precedence over `body`. |
| `body` | `http-request`, `http-post` | Raw request body string. |
| `bearer` | all | Bearer token. Sent as `Authorization: Bearer <token>`. Never logged. |
| `basic_user` | all | Username for HTTP Basic auth. |
| `basic_pass` | all | Password for HTTP Basic auth. Never logged. |
| `allow_private` | all | Set to `true` to permit private/loopback/link-local targets (trusted local services only). |

## SSRF protection

The SSRF guard is on by default. Before any socket opens, every A/AAAA record
returned by DNS is checked. Blocked ranges:

- IPv4 loopback (127.0.0.0/8)
- IPv4 private (10/8, 172.16/12, 192.168/16)
- IPv4 link-local and cloud metadata (169.254.0.0/16, including 169.254.169.254)
- IPv4 carrier-grade NAT (100.64.0.0/10, RFC 6598)
- IPv4 multicast and broadcast
- IPv6 loopback (::1), ULA (fc00::/7), link-local (fe80::/10), multicast (ff00::/8)
- IPv4-mapped IPv6 (`::ffff:0:0/96`) -- re-validated as IPv4 to close the bypass

Redirects are not followed; a `302` to a private IP cannot bypass the guard.
Only `http` and `https` are accepted as URL schemes.

Pass `allow_private=true` to opt out for trusted local services.

## Requirements

- macOS 13+ (uses Foundation's `URLSession`; macOS-only platform target)
- Swift 6 toolchain (to build from source)

## Install

```bash
fledge plugins install CorvidLabs/fledge-plugin-http
```

## Build from source

```bash
swift build -c release
```

## License

MIT
