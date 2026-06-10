@preconcurrency import Foundation

// MARK: - SSRF Guard

/// Validates that every resolved IP for a host is safe to dial.
///
/// The guard runs before any socket opens; validated addresses are returned
/// for use as pinned overrides so a low-TTL hostile DNS cannot rebind
/// between the pre-flight and the real connect.
///
/// Refused ranges:
/// - IPv4 loopback (127.0.0.0/8)
/// - IPv4 private (10/8, 172.16/12, 192.168/16)
/// - IPv4 link-local and cloud-metadata (169.254.0.0/16, includes 169.254.169.254)
/// - IPv4 carrier-grade NAT (100.64.0.0/10, RFC 6598)
/// - IPv4 broadcast and unspecified (0.0.0.0, 255.255.255.255)
/// - IPv4 multicast (224.0.0.0/4)
/// - IPv6 loopback (::1) and unspecified (::)
/// - IPv6 ULA (fc00::/7)
/// - IPv6 link-local (fe80::/10)
/// - IPv6 multicast (ff00::/8)
/// - IPv4-mapped IPv6 (::ffff:0:0/96) -- re-validated as IPv4 to close
///   the `::ffff:127.0.0.1` bypass
internal enum SSRFGuard {
    /// The placeholder shown in error messages when a secret value must not be echoed.
    internal static let redacted = "<redacted>"

    /// Resolve `host` on `port`, validate every returned address, and return
    /// the pinned socket addresses for use in `URLSessionConfiguration`.
    ///
    /// - Parameters:
    ///   - host: The hostname (or IP literal) from the request URL.
    ///   - port: The port to pair with each resolved address.
    ///   - allowPrivate: When `true`, skip the IP validation step.
    /// - Returns: The resolved and validated socket address strings.
    /// - Throws: `SSRFError` when any address is private and `allowPrivate` is false.
    internal static func resolve(
        host: String,
        port: Int,
        allowPrivate: Bool
    ) throws -> [String] {
        let addresses = try dnsResolve(host: host, port: port)
        if addresses.isEmpty {
            throw SSRFError.noRecords(host)
        }
        if !allowPrivate {
            for address in addresses {
                guard isPublicIP(address) else {
                    throw SSRFError.blocked(host: host, ip: address)
                }
            }
        }
        return addresses
    }

    /// Returns `true` when the IP address string represents a globally routable
    /// address (not loopback, private, link-local, multicast, metadata, etc.).
    internal static func isPublicIP(_ addressString: String) -> Bool {
        // Strip the port suffix if present (e.g. "1.2.3.4:443").
        let hostPart: String
        if addressString.hasPrefix("[") {
            // IPv6 literal with port: [::1]:443
            if let bracket = addressString.firstIndex(of: "]") {
                hostPart = String(addressString[addressString.index(after: addressString.startIndex)..<bracket])
            } else {
                hostPart = addressString
            }
        } else if addressString.contains(":") && !addressString.filter({ $0 == ":" }).count.isMultiple(of: 2) {
            // Plain IPv6 literal without brackets
            hostPart = addressString
        } else if let colon = addressString.lastIndex(of: ":") {
            // IPv4 with port or plain IPv4
            let candidate = String(addressString[..<colon])
            if candidate.contains(":") {
                // IPv6 with port but no brackets - unlikely, take the whole string
                hostPart = addressString
            } else {
                hostPart = candidate
            }
        } else {
            hostPart = addressString
        }

        // Try to parse as IPv4 first.
        if let v4 = parseIPv4(hostPart) {
            return isPublicIPv4(v4)
        }

        // Try IPv6.
        if let v6 = parseIPv6(hostPart) {
            return isPublicIPv6(v6)
        }

        // Unparseable -- fail safe.
        return false
    }

    // MARK: - Private helpers

    private static func isPublicIPv4(_ octets: (UInt8, UInt8, UInt8, UInt8)) -> Bool {
        let (a, b, c, d) = octets
        // Loopback: 127.0.0.0/8
        if a == 127 { return false }
        // Unspecified: 0.0.0.0/8
        if a == 0 { return false }
        // Private: 10.0.0.0/8
        if a == 10 { return false }
        // Private: 172.16.0.0/12
        if a == 172 && (16...31).contains(b) { return false }
        // Private: 192.168.0.0/16
        if a == 192 && b == 168 { return false }
        // Link-local and cloud metadata: 169.254.0.0/16 (covers 169.254.169.254)
        if a == 169 && b == 254 { return false }
        // Carrier-grade NAT: 100.64.0.0/10 (RFC 6598)
        if a == 100 && (64...127).contains(b) { return false }
        // Multicast: 224.0.0.0/4
        if (224...239).contains(a) { return false }
        // Broadcast: 255.255.255.255
        if a == 255 && b == 255 && c == 255 && d == 255 { return false }
        // Documentation/test: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        if a == 192 && b == 0 && c == 2 { return false }
        if a == 198 && b == 51 && c == 100 { return false }
        if a == 203 && b == 0 && c == 113 { return false }
        return true
    }

    private static func isPublicIPv6(_ segments: [UInt16]) -> Bool {
        guard segments.count == 8 else { return false }
        let s = segments
        // Loopback: ::1
        if s == [0, 0, 0, 0, 0, 0, 0, 1] { return false }
        // Unspecified: ::
        if s == [0, 0, 0, 0, 0, 0, 0, 0] { return false }
        // IPv4-mapped: ::ffff:0:0/96 -- re-validate the embedded IPv4
        if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0xffff {
            let hi = UInt8(s[6] >> 8)
            let lo = UInt8(s[6] & 0xff)
            let hiLow = UInt8(s[7] >> 8)
            let loLow = UInt8(s[7] & 0xff)
            return isPublicIPv4((hi, lo, hiLow, loLow))
        }
        // IPv4-compatible: ::0:0/96 (deprecated but close the hole)
        if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
            if s[6] != 0 || s[7] != 1 { // not ::1 (already caught)
                let hi = UInt8(s[6] >> 8)
                let lo = UInt8(s[6] & 0xff)
                let hiLow = UInt8(s[7] >> 8)
                let loLow = UInt8(s[7] & 0xff)
                return isPublicIPv4((hi, lo, hiLow, loLow))
            }
        }
        // ULA: fc00::/7
        if (s[0] & 0xfe00) == 0xfc00 { return false }
        // Link-local: fe80::/10
        if (s[0] & 0xffc0) == 0xfe80 { return false }
        // Multicast: ff00::/8
        if (s[0] & 0xff00) == 0xff00 { return false }
        return true
    }

    /// Resolve `host:port` to a list of IP address strings using
    /// Foundation's `getaddrinfo` wrapper.
    private static func dnsResolve(host: String, port: Int) throws -> [String] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM

        var result: UnsafeMutablePointer<addrinfo>?
        let portString = "\(port)"
        let status = getaddrinfo(host, portString, &hints, &result)
        guard status == 0, let head = result else {
            throw SSRFError.resolveFailed(host: host, reason: String(cString: gai_strerror(status)))
        }
        defer { freeaddrinfo(head) }

        var addresses: [String] = []
        var current: UnsafeMutablePointer<addrinfo>? = head
        while let node = current {
            if let addrStr = sockaddrToString(node.pointee.ai_addr, node.pointee.ai_addrlen) {
                addresses.append(addrStr)
            }
            current = node.pointee.ai_next
        }
        return addresses
    }

    /// Convert a `sockaddr` pointer to a human-readable IP string (no port).
    private static func sockaddrToString(
        _ sa: UnsafeMutablePointer<sockaddr>?,
        _ len: socklen_t
    ) -> String? {
        guard let sa else { return nil }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        switch Int32(sa.pointee.sa_family) {
        case AF_INET:
            return sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                var addr = sin.pointee.sin_addr
                guard inet_ntop(AF_INET, &addr, &buf, socklen_t(buf.count)) != nil else {
                    return nil
                }
                // Trim the null terminator before constructing the Swift string.
                let terminated = buf.firstIndex(of: 0).map { buf[..<$0] } ?? buf[...]
                return String(decoding: terminated.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            }
        case AF_INET6:
            return sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                var addr = sin6.pointee.sin6_addr
                guard inet_ntop(AF_INET6, &addr, &buf, socklen_t(buf.count)) != nil else {
                    return nil
                }
                let terminated = buf.firstIndex(of: 0).map { buf[..<$0] } ?? buf[...]
                return String(decoding: terminated.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            }
        default:
            return nil
        }
    }

    // MARK: - IPv4/IPv6 parsers

    /// Parse a dotted-decimal IPv4 string to its four octets.
    internal static func parseIPv4(_ string: String) -> (UInt8, UInt8, UInt8, UInt8)? {
        let parts = string.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        guard
            let a = UInt8(parts[0]),
            let b = UInt8(parts[1]),
            let c = UInt8(parts[2]),
            let d = UInt8(parts[3])
        else { return nil }
        return (a, b, c, d)
    }

    /// Parse an IPv6 address string (without brackets or port) to its eight 16-bit segments.
    ///
    /// Handles both full hex notation (`2001:db8::1`) and mixed notation
    /// (`::ffff:192.0.2.1`) where the last 32 bits are expressed as a dotted-decimal
    /// IPv4 address.
    internal static func parseIPv6(_ string: String) -> [UInt16]? {
        // Reject plain IPv4 (no colons).
        guard string.contains(":") else { return nil }

        let str = string.hasPrefix("[") && string.hasSuffix("]")
            ? String(string.dropFirst().dropLast())
            : string

        // Mixed notation: the last group may be a dotted-decimal IPv4 address.
        // Examples: "::ffff:1.2.3.4", "64:ff9b::192.0.2.1"
        // Convert the trailing IPv4 part to two 16-bit hex groups first.
        var normalized = str
        var trailingIPv4: [UInt16]?
        if let colonIdx = str.lastIndex(of: ":") {
            let lastGroup = String(str[str.index(after: colonIdx)...])
            if lastGroup.contains("."), let v4 = parseIPv4(lastGroup) {
                let hi = UInt16(v4.0) << 8 | UInt16(v4.1)
                let lo = UInt16(v4.2) << 8 | UInt16(v4.3)
                trailingIPv4 = [hi, lo]
                // Replace the IPv4 part with "0:0" as placeholder to keep group count right.
                normalized = String(str[...colonIdx]) + "0:0"
            }
        }

        // Split on "::" to find the compressed zero run.
        let halves = normalized.components(separatedBy: "::")
        guard halves.count <= 2 else { return nil }

        func parseHalf(_ s: String) -> [UInt16]? {
            guard !s.isEmpty else { return [] }
            let groups = s.split(separator: ":", omittingEmptySubsequences: false)
            var result: [UInt16] = []
            for g in groups {
                guard let val = UInt16(g, radix: 16) else { return nil }
                result.append(val)
            }
            return result
        }

        var segments: [UInt16]
        if halves.count == 1 {
            guard let segs = parseHalf(halves[0]), segs.count == 8 else { return nil }
            segments = segs
        } else {
            guard
                let left = parseHalf(halves[0]),
                let right = parseHalf(halves[1])
            else { return nil }
            let zerosNeeded = 8 - left.count - right.count
            guard zerosNeeded >= 0 else { return nil }
            segments = left + [UInt16](repeating: 0, count: zerosNeeded) + right
        }

        // Overwrite the placeholder with the real IPv4 segments if we had mixed notation.
        if let v4segs = trailingIPv4 {
            segments[6] = v4segs[0]
            segments[7] = v4segs[1]
        }

        guard segments.count == 8 else { return nil }
        return segments
    }
}

// MARK: - SSRFError

internal enum SSRFError: Error, CustomStringConvertible, LocalizedError, Sendable {
    case noRecords(String)
    case resolveFailed(host: String, reason: String)
    case blocked(host: String, ip: String)

    internal var description: String {
        switch self {
        case .noRecords(let host):
            return "dns returned no records for \(host)"
        case .resolveFailed(let host, let reason):
            return "dns resolve failed for \(host): \(reason)"
        case .blocked(let host, let ip):
            return "blocked: \(host) resolves to non-public IP \(ip) " +
                "(loopback / private / link-local / multicast / metadata). " +
                "Pass allow_private=true to override for trusted local services."
        }
    }

    internal var errorDescription: String? { description }
}
