// MARK: - Error redaction

/// Strip any `Bearer <token>` or `Basic <credentials>` substrings from an
/// error message so authorization material is never written to logs or
/// echoed back in a user-visible error.
///
/// - Parameter message: The raw error string from a transport layer.
/// - Returns: The same string with secret tokens replaced by `"<redacted>"`.
internal func redactError(_ message: String) -> String {
    let schemes = ["Bearer ", "Basic "]
    var result = ""
    var remaining = message[...]

    while !remaining.isEmpty {
        // Find the earliest occurrence of any auth scheme.
        var earliest: (index: String.Index, scheme: String)?
        for scheme in schemes {
            if let range = remaining.range(of: scheme) {
                if earliest == nil || range.lowerBound < earliest!.index {
                    earliest = (range.lowerBound, scheme)
                }
            }
        }

        guard let match = earliest else {
            // No more secret markers -- append the rest verbatim.
            result += remaining
            break
        }

        // Append everything before the scheme word.
        result += remaining[..<match.index]
        // Advance past the scheme word.
        let afterScheme = remaining[remaining.index(match.index, offsetBy: match.scheme.count)...]
        // Append the scheme name (not secret) then redact the token.
        result += match.scheme
        result += redacted
        // Skip the token (everything up to the next whitespace or end).
        if let spaceIdx = afterScheme.firstIndex(where: { $0.isWhitespace }) {
            remaining = afterScheme[spaceIdx...]
        } else {
            remaining = afterScheme[afterScheme.endIndex...]
        }
    }

    return result
}
