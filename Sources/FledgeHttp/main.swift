@preconcurrency import Foundation

// MARK: - Entry point

let io = PluginIO()

let init_: InitMessage
do {
    init_ = try io.receiveInit()
} catch {
    fputs("fledge-http: failed to read init: \(error)\n", stderr)
    exit(1)
}

// Derive the command from the fledge `command` field if present, otherwise
// fall back to argv[0] (the installed symlink name). fledge creates a symlink
// `fledge-http-request` -> `.build/release/fledge-http`, so stripping the
// `fledge-` prefix from argv[0]'s last path component gives the command name.
let command: String = {
    if let cmd = init_.command, !cmd.isEmpty { return cmd }
    return commandFromArgv()
}()

func usageText() -> String {
    """
    fledge-http — make an HTTP(S) request behind an SSRF guard.

    Commands:
      http-request  <url> [method] [headers_json] [body]  Generic request (default GET)
      http-get      <url> [headers_json]                  Convenience GET
      http-post     <url> [body] [headers_json]           Convenience POST

    Returns a JSON envelope: { status, ok, content_type, headers, body, truncated, elapsed_ms }.
    Requests to non-public addresses (loopback, private, link-local, metadata) are refused.
    """
}

let result: Result<String, Error>
switch command {
case "http-request":
    result = Result { try runRequest(args: init_.args, methodOverride: nil) }
case "http-get":
    result = Result { try runRequest(args: init_.args, methodOverride: .get) }
case "http-post":
    result = Result { try runRequest(args: init_.args, methodOverride: .post) }
case "", "help", "--help", "-h":
    // No command (binary run without a symlink/command field) or an explicit
    // help request: print usage rather than treating it as an unknown command.
    io.output(usageText() + "\n")
    exit(0)
default:
    io.output(
        "Unknown command: \(command)\nExpected: http-request, http-get, http-post\n\n"
            + usageText() + "\n"
    )
    exit(0)
}

switch result {
case .success(let output):
    io.output(output)
case .failure(let error):
    io.log(level: "error", error.localizedDescription)
    exit(1)
}
