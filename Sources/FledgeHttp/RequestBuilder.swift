@preconcurrency import Foundation

// MARK: - Constants

/// Maximum bytes of the response body returned to the agent. 64 KB is generous
/// for an API payload while staying bounded enough to avoid blowing the context
/// window of an LLM that reads the output.
internal let maxBodyBytes = 64 * 1024

/// Maximum bytes read from the network before we stop. Leaves headroom above
/// `maxBodyBytes` so that truncation can be detected and flagged.
internal let maxFetchBytes = 8 * 1024 * 1024

/// Per-request timeout. Well-behaved APIs respond in under a second; anything
/// longer than 20 s is almost certainly stalled infrastructure.
internal let requestTimeout: TimeInterval = 20

/// Substituted for any secret-bearing header value when echoed in an error.
internal let redacted = "<redacted>"

// MARK: - HTTP Method

/// The HTTP methods this plugin allows.
internal enum HTTPMethod: String, Sendable {
    case get = "GET"
    case post = "POST"
    case put = "PUT"
    case patch = "PATCH"
    case delete = "DELETE"

    /// Parse a case-insensitive method string.
    /// - Parameter raw: The raw method string (e.g. "get", "POST").
    /// - Returns: The matching method, or `nil` for disallowed methods.
    internal static func parse(_ raw: String) -> HTTPMethod? {
        switch raw.uppercased() {
        case "GET":    return .get
        case "POST":   return .post
        case "PUT":    return .put
        case "PATCH":  return .patch
        case "DELETE": return .delete
        default:       return nil
        }
    }
}

// MARK: - PreparedRequest

/// A fully validated request ready for dispatch. Building a `PreparedRequest`
/// is a pure operation -- no network, no side-effects -- making it easy to
/// unit-test all validation logic independently.
internal struct PreparedRequest: Sendable {
    internal let method: HTTPMethod
    internal let url: URL
    internal let headers: [(name: String, value: String)]
    internal let body: Data?
    internal let allowPrivate: Bool
}

// MARK: - Arg parser

/// Parse a flat `--key value` argument list into a `[String: String]` map.
///
/// Supports all-named (`--url U --method POST`), all-positional, and mixed
/// shapes. A trailing `--flag` with no following value is dropped. Repeated
/// `--flag` is last-write-wins.
///
/// - Parameters:
///   - args: The raw argument list from the init message.
///   - declared: Ordered parameter names used for positional slot assignment.
/// - Returns: A dictionary of resolved key/value pairs.
internal func parseArgs(_ args: [String], declared: [String]) -> [String: String] {
    var out: [String: String] = [:]
    var nextPositionalSlot = 0
    var index = 0
    while index < args.count {
        let arg = args[index]
        if let name = arg.hasPrefix("--") ? String(arg.dropFirst(2)) : nil, !name.isEmpty {
            let nextIsValue = (index + 1 < args.count) && !args[index + 1].hasPrefix("--")
            if nextIsValue {
                out[name] = args[index + 1]
                index += 2
            } else {
                index += 1
            }
        } else {
            // Positional: skip already-filled slots.
            while nextPositionalSlot < declared.count && out[declared[nextPositionalSlot]] != nil {
                nextPositionalSlot += 1
            }
            if nextPositionalSlot < declared.count {
                out[declared[nextPositionalSlot]] = arg
                nextPositionalSlot += 1
            }
            index += 1
        }
    }
    return out
}

// MARK: - Request preparation

/// Whether a header name carries secret material that must never be echoed.
internal func isSecretHeader(_ name: String) -> Bool {
    let lower = name.lowercased()
    return lower == "authorization" || lower == "proxy-authorization"
}

/// Validate that a header name and value contain no control characters.
///
/// Header names must be non-empty visible ASCII (no colon, no controls).
/// Header values must not contain CR, LF, or NUL -- any of which could
/// split or inject headers. Secret-bearing values are redacted in the
/// error message so authorization material is never echoed.
///
/// - Parameters:
///   - name: The header name.
///   - value: The header value.
/// - Throws: `RequestError.invalidHeader` on validation failure.
internal func validateHeader(name: String, value: String) throws {
    guard !name.isEmpty else {
        throw RequestError.invalidHeader("empty header name")
    }
    let badNameByte = name.unicodeScalars.contains { scalar in
        let v = scalar.value
        return !(0x21...0x7e).contains(v) || v == UInt32(UInt8(ascii: ":"))
    }
    if badNameByte {
        throw RequestError.invalidHeader("invalid characters in header name \(name.debugDescription)")
    }
    let hasControlChar = value.unicodeScalars.contains { scalar in
        scalar.value == 0x0d || scalar.value == 0x0a || scalar.value == 0
    }
    if hasControlChar {
        let shown = isSecretHeader(name) ? redacted : value.debugDescription
        throw RequestError.invalidHeader(
            "invalid control characters in header value for \(shown)"
        )
    }
}

/// Convert a JSON scalar value (string, number, bool) to its string form.
/// Returns `nil` for arrays, objects, and null.
private func jsonScalarToString(_ value: Any) -> String? {
    switch value {
    case let s as String: return s
    case let n as NSNumber:
        // Distinguish bool (CFBooleanRef) from numeric.
        if CFGetTypeID(n) == CFBooleanGetTypeID() {
            return n.boolValue ? "true" : "false"
        }
        return n.stringValue
    default: return nil
    }
}

/// Build a `PreparedRequest` from parsed arguments.
///
/// `methodOverride` is set by the `http-get` and `http-post` convenience
/// commands; it wins over any `method` arg the caller supplies.
///
/// - Parameters:
///   - parsed: The argument map produced by `parseArgs(_:declared:)`.
///   - methodOverride: When non-nil, forces the HTTP method regardless of args.
/// - Returns: A validated `PreparedRequest`.
/// - Throws: `RequestError` for any validation failure.
internal func prepareRequest(
    parsed: [String: String],
    methodOverride: HTTPMethod?
) throws -> PreparedRequest {
    guard let rawURL = parsed["url"] else {
        throw RequestError.missingArgument("url")
    }
    guard let url = URL(string: rawURL), let scheme = url.scheme?.lowercased() else {
        throw RequestError.invalidURL("invalid url: \(rawURL)")
    }
    guard scheme == "http" || scheme == "https" else {
        throw RequestError.invalidURL("scheme \"\(scheme)\" not allowed; use http or https")
    }

    // Method: convenience-command override wins; else the `method` arg; else GET.
    let method: HTTPMethod
    if let override = methodOverride {
        method = override
    } else if let rawMethod = parsed["method"] {
        guard let parsed = HTTPMethod.parse(rawMethod) else {
            throw RequestError.invalidMethod("method \"\(rawMethod)\" not allowed")
        }
        method = parsed
    } else {
        method = .get
    }

    // Query params from a JSON object -> appended to the URL.
    var components = URLComponents(url: url, resolvingAgainstBaseURL: false) ?? URLComponents()
    if let rawQuery = parsed["query"] {
        guard
            let data = rawQuery.data(using: .utf8),
            let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else {
            throw RequestError.invalidJSON("invalid query json: \(rawQuery)")
        }
        var items = components.queryItems ?? []
        for (key, val) in obj {
            guard let valStr = jsonScalarToString(val) else {
                throw RequestError.invalidJSON("query value for \"\(key)\" must be a scalar")
            }
            items.append(URLQueryItem(name: key, value: valStr))
        }
        components.queryItems = items.isEmpty ? nil : items
    }
    guard let resolvedURL = components.url else {
        throw RequestError.invalidURL("could not reconstruct URL after applying query params")
    }

    // Headers from a JSON object.
    var headers: [(name: String, value: String)] = []
    if let rawHeaders = parsed["headers"] {
        guard
            let data = rawHeaders.data(using: .utf8),
            let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else {
            throw RequestError.invalidJSON("invalid headers json: \(rawHeaders)")
        }
        for (key, val) in obj {
            guard let valStr = jsonScalarToString(val) else {
                throw RequestError.invalidJSON("header value for \"\(key)\" must be a scalar")
            }
            try validateHeader(name: key, value: valStr)
            headers.append((name: key, value: valStr))
        }
    }

    // Auth: bearer token -> Authorization: Bearer <token>
    if let token = parsed["bearer"] {
        guard !token.isEmpty else {
            throw RequestError.invalidArgument("bearer token is empty")
        }
        let value = "Bearer \(token)"
        try validateHeader(name: "authorization", value: value)
        headers.append((name: "authorization", value: value))
    }

    // Auth: HTTP basic auth -> Authorization: Basic <base64(user:pass)>
    if let user = parsed["basic_user"] {
        let pass = parsed["basic_pass"] ?? ""
        let credentials = "\(user):\(pass)"
        let encoded = Data(credentials.utf8).base64EncodedString()
        let value = "Basic \(encoded)"
        try validateHeader(name: "authorization", value: value)
        headers.append((name: "authorization", value: value))
    }

    // Body: `json` arg takes precedence over `body`.
    var body: Data?
    if let rawJSON = parsed["json"] {
        guard
            let jsonData = rawJSON.data(using: .utf8),
            let obj = try? JSONSerialization.jsonObject(with: jsonData)
        else {
            throw RequestError.invalidJSON("invalid json body: \(rawJSON)")
        }
        let serialized = try JSONSerialization.data(withJSONObject: obj)
        // Only inject content-type when the caller hasn't already set it.
        let hasContentType = headers.contains { $0.name.lowercased() == "content-type" }
        if !hasContentType {
            headers.append((name: "content-type", value: "application/json"))
        }
        body = serialized
    } else if let rawBody = parsed["body"] {
        body = rawBody.data(using: .utf8)
    }

    let allowPrivate = parsed["allow_private"].map { v in
        let lower = v.lowercased()
        return lower == "true" || lower == "1" || lower == "yes"
    } ?? false

    return PreparedRequest(
        method: method,
        url: resolvedURL,
        headers: headers,
        body: body,
        allowPrivate: allowPrivate
    )
}

// MARK: - RequestError

internal enum RequestError: Error, CustomStringConvertible, LocalizedError, Sendable {
    case missingArgument(String)
    case invalidURL(String)
    case invalidMethod(String)
    case invalidJSON(String)
    case invalidHeader(String)
    case invalidArgument(String)

    internal var description: String {
        switch self {
        case .missingArgument(let name): return "missing \(name) argument"
        case .invalidURL(let msg):       return msg
        case .invalidMethod(let msg):    return msg
        case .invalidJSON(let msg):      return msg
        case .invalidHeader(let msg):    return msg
        case .invalidArgument(let msg):  return msg
        }
    }

    internal var errorDescription: String? { description }
}
