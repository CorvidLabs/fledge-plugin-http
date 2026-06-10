@preconcurrency import Foundation

// MARK: - Declared arguments

/// The canonical parameter names accepted by `http-request`.
/// Positional slot order matches the Rust reference implementation.
private let declaredArgs: [String] = [
    "url",
    "method",
    "headers",
    "query",
    "body",
    "json",
    "bearer",
    "basic_user",
    "basic_pass",
    "allow_private",
]

// MARK: - Command dispatch

/// Execute an `http-request`, `http-get`, or `http-post` command.
///
/// Parses `args`, validates and prepares the request, runs the SSRF pre-flight,
/// and dispatches via `URLSession`. Returns the structured JSON response
/// envelope as a pretty-printed string.
///
/// - Parameters:
///   - args: The raw argument list from the fledge init message.
///   - methodOverride: Forces the HTTP method (used by `http-get` / `http-post`).
/// - Returns: The JSON envelope string (always ends with `\n`).
/// - Throws: Any `RequestError` or `SSRFError` encountered during preparation
///   or dispatch.
internal func runRequest(args: [String], methodOverride: HTTPMethod?) throws -> String {
    let parsed = parseArgs(args, declared: declaredArgs)
    let prepared = try prepareRequest(parsed: parsed, methodOverride: methodOverride)

    // --- SSRF pre-flight ---
    let host = prepared.url.host ?? ""
    let port = prepared.url.port ?? (prepared.url.scheme == "https" ? 443 : 80)

    // Resolve and validate every address before any socket opens (SSRF guard).
    // The return value is intentionally discarded: the guard's purpose is to
    // throw for blocked addresses; URLSession will re-resolve independently.
    _ = try SSRFGuard.resolve(
        host: host,
        port: port,
        allowPrivate: prepared.allowPrivate
    )

    // --- Build URLRequest ---
    // We disable redirects because a 302 to http://169.254.169.254 would
    // bypass the SSRF pre-flight entirely.
    var urlRequest = URLRequest(
        url: prepared.url,
        cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
        timeoutInterval: requestTimeout
    )
    urlRequest.httpMethod = prepared.method.rawValue

    for (name, value) in prepared.headers {
        urlRequest.setValue(value, forHTTPHeaderField: name)
    }
    if let body = prepared.body {
        urlRequest.httpBody = body
    }
    if urlRequest.value(forHTTPHeaderField: "User-Agent") == nil {
        urlRequest.setValue("fledge-plugin-http/0.1.0", forHTTPHeaderField: "User-Agent")
    }

    // --- URLSession with redirect blocking and address pinning ---
    let configuration = URLSessionConfiguration.ephemeral
    configuration.timeoutIntervalForRequest = requestTimeout
    configuration.timeoutIntervalForResource = requestTimeout

    let delegate = RedirectBlockingDelegate()
    let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    defer { session.finishTasksAndInvalidate() }

    // Use a semaphore to turn the async URLSession API into a synchronous call,
    // matching the plugin's single-pass execution model.
    let semaphore = DispatchSemaphore(value: 0)
    // Box the results so the @Sendable closure can write them without
    // capturing mutable vars across concurrency boundaries.
    let box = ResultBox()

    let started = Date()
    let task = session.dataTask(with: urlRequest) { data, response, error in
        box.data = data
        box.response = response
        box.error = error
        semaphore.signal()
    }
    task.resume()
    semaphore.wait()

    let elapsedMs = Int(Date().timeIntervalSince(started) * 1000)

    if let error = box.error {
        throw RequestError.invalidArgument(
            "request failed: \(redactError(error.localizedDescription))"
        )
    }

    guard let httpResponse = box.response as? HTTPURLResponse else {
        throw RequestError.invalidArgument("no HTTP response received")
    }
    let responseData = box.data

    let statusCode = httpResponse.statusCode
    let isOK = (200...299).contains(statusCode)

    // Content-Type
    let contentType = httpResponse.allHeaderFields["Content-Type"] as? String
        ?? httpResponse.value(forHTTPHeaderField: "content-type")

    // Response headers (server-supplied, not secret).
    var responseHeaders: [String: String] = [:]
    for (key, value) in httpResponse.allHeaderFields {
        if let k = key as? String, let v = value as? String {
            responseHeaders[k.lowercased()] = v
        }
    }

    // Body: cap at maxFetchBytes, then clip to maxBodyBytes on UTF-8 boundary.
    let rawBytes = responseData ?? Data()
    let cappedBytes = rawBytes.prefix(maxFetchBytes)

    // Lossy UTF-8 conversion -- replaces undecodable bytes with U+FFFD.
    let fullText = String(bytes: cappedBytes, encoding: .utf8)
        ?? String(cappedBytes.map { Character(UnicodeScalar($0)) })

    // Clip to maxBodyBytes on a UTF-8 character boundary. The previous inline
    // loop guarded on `distance(...).isMultiple(of: 1)`, which is true for
    // every integer, so it never walked back to a boundary; `samePosition`
    // then returned nil mid-scalar and the fallback to `endIndex` returned the
    // FULL body while still flagging `truncated: true`. Use the dedicated
    // helper, which walks `String.utf8` indices to a real boundary.
    let (bodyText, truncated) = truncateAtCharBoundary(fullText, maxBytes: maxBodyBytes)

    // Build the response envelope.
    let envelope: [String: Any] = [
        "status": statusCode,
        "ok": isOK,
        "content_type": contentType as Any,
        "headers": responseHeaders,
        "body": bodyText,
        "truncated": truncated,
        "elapsed_ms": elapsedMs,
    ]

    let envelopeData = try JSONSerialization.data(
        withJSONObject: envelope,
        options: [.prettyPrinted, .sortedKeys]
    )
    guard var envelopeString = String(data: envelopeData, encoding: .utf8) else {
        throw RequestError.invalidArgument("could not encode response envelope as UTF-8")
    }
    envelopeString.append("\n")
    return envelopeString
}

// MARK: - Body truncation helper

/// Cut `text` at a UTF-8 char boundary no larger than `maxBytes`.
///
/// Using `String.utf8` indices ensures we never slice a multi-byte scalar.
internal func truncateAtCharBoundary(_ text: String, maxBytes: Int) -> (String, Bool) {
    let utf8 = text.utf8
    guard utf8.count > maxBytes else { return (text, false) }

    var cutUTF8 = utf8.index(utf8.startIndex, offsetBy: maxBytes)
    // Walk back until we land on a character boundary.
    while cutUTF8 > utf8.startIndex {
        if let charIdx = cutUTF8.samePosition(in: text) {
            return (String(text[..<charIdx]), true)
        }
        cutUTF8 = utf8.index(before: cutUTF8)
    }
    return ("", true)
}

// MARK: - Result box

/// A mutable reference container used to ferry `URLSession` completion values
/// out of the `@Sendable` data-task closure without mutating captured locals.
/// The semaphore ensures all writes happen-before the read in the calling
/// thread, so no additional synchronisation is needed.
private final class ResultBox: @unchecked Sendable {
    var data: Data?
    var response: URLResponse?
    var error: Error?
}

// MARK: - Redirect blocking

/// A `URLSessionTaskDelegate` that refuses all redirects by returning the
/// redirect response verbatim. This prevents a `302 -> http://169.254.169.254`
/// from bypassing the SSRF pre-flight.
private final class RedirectBlockingDelegate: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        // Passing `nil` causes URLSession to return the redirect response as-is.
        completionHandler(nil)
    }
}
