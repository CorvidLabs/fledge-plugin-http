@preconcurrency import Foundation

// MARK: - Inbound (fledge -> plugin)

/// The init message fledge sends over stdin when the plugin binary starts.
///
/// fledge serializes this as a single JSON line. The `command` field is absent
/// in current fledge versions; the plugin derives it from `argv[0]` by
/// stripping the `fledge-` prefix so that symlinks named
/// `fledge-http-request`, `fledge-http-get`, and `fledge-http-post` all
/// map to distinct commands within one binary.
internal struct InitMessage: Decodable, Sendable {
    internal let type: String
    internal let `protocol`: String
    internal let command: String?
    internal let args: [String]
    internal let project: ProjectInfo?
    internal let plugin: PluginInfo
    internal let fledge: FledgeInfo
}

internal struct ProjectInfo: Decodable, Sendable {
    internal let name: String
    internal let root: String
    internal let language: String?
    internal let git: GitInfo?
}

internal struct GitInfo: Decodable, Sendable {
    internal let branch: String
    internal let dirty: Bool
}

internal struct PluginInfo: Decodable, Sendable {
    internal let name: String
    internal let version: String
    internal let dir: String
}

internal struct FledgeInfo: Decodable, Sendable {
    internal let version: String
}

// MARK: - Outbound (plugin -> fledge)

/// A message the plugin sends back to fledge over stdout.
internal enum OutboundMessage: Encodable, Sendable {
    /// User-visible text output. This is the normal result payload.
    case output(String)
    /// A structured log entry shown in fledge's diagnostic stream.
    case log(level: String, message: String)

    private enum CodingKeys: String, CodingKey {
        case type, text, level, message
    }

    internal func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .output(let text):
            try container.encode("output", forKey: .type)
            try container.encode(text, forKey: .text)
        case .log(let level, let message):
            try container.encode("log", forKey: .type)
            try container.encode(level, forKey: .level)
            try container.encode(message, forKey: .message)
        }
    }
}

// MARK: - PluginIO

/// Manages the fledge-v1 JSON-lines stdin/stdout channel for this plugin.
///
/// The protocol is:
/// 1. fledge writes one JSON line (the init message) to the plugin's stdin.
/// 2. The plugin reads that line and dispatches to the appropriate command.
/// 3. The plugin writes one or more JSON lines back to stdout (log entries,
///    then a final output message).
/// 4. Both sides close when the plugin exits.
internal final class PluginIO: Sendable {
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    internal init() {
        let enc = JSONEncoder()
        enc.outputFormatting = []
        self.encoder = enc
        self.decoder = JSONDecoder()
    }

    /// Read and decode the single init message from stdin.
    ///
    /// - Returns: The decoded `InitMessage`.
    /// - Throws: `PluginError.initFailed` if stdin is empty or the JSON is malformed.
    internal func receiveInit() throws -> InitMessage {
        guard let line = readLine(strippingNewline: true), !line.isEmpty else {
            throw PluginError.initFailed("expected init message on stdin, got EOF")
        }
        guard let data = line.data(using: .utf8) else {
            throw PluginError.initFailed("init message contained non-UTF-8 bytes")
        }
        return try decoder.decode(InitMessage.self, from: data)
    }

    /// Send a message to fledge as a JSON line on stdout.
    ///
    /// - Parameter message: The `OutboundMessage` to serialize and emit.
    /// - Throws: `PluginError.writeFailed` if encoding or writing fails.
    internal func send(_ message: OutboundMessage) throws {
        let data = try encoder.encode(message)
        guard var line = String(data: data, encoding: .utf8) else {
            throw PluginError.writeFailed("could not encode outbound message as UTF-8")
        }
        line.append("\n")
        print(line, terminator: "")
        fflush(stdout)
    }

    /// Convenience: emit a user-visible text result.
    internal func output(_ text: String) {
        try? send(.output(text))
    }

    /// Convenience: emit a log entry at `level`.
    internal func log(level: String = "error", _ message: String) {
        try? send(.log(level: level, message: message))
    }
}

// MARK: - PluginError

internal enum PluginError: Error, Sendable {
    case initFailed(String)
    case writeFailed(String)
}

// MARK: - Command resolution

/// Derives the active command name from `argv[0]`.
///
/// fledge installs symlinks named `fledge-<command>` pointing at the binary.
/// Stripping `fledge-` from the last path component gives the command name,
/// e.g. `fledge-http-request` -> `http-request`.
///
/// - Parameter fallback: Returned when argv[0] cannot be resolved to a command.
internal func commandFromArgv(fallback: String = "") -> String {
    guard let argv0 = CommandLine.arguments.first else { return fallback }
    let base = URL(fileURLWithPath: argv0).lastPathComponent
    // The binary name is "fledge-<command>"; drop the "fledge-" prefix.
    // The command itself may contain hyphens (e.g. "http-request"), so we
    // rejoin everything after the first component.
    let parts = base.components(separatedBy: "-").dropFirst()
    guard !parts.isEmpty else { return fallback }
    return parts.joined(separator: "-")
}
