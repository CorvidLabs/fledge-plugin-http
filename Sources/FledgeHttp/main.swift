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

let result: Result<String, Error>
switch command {
case "http-request":
    result = Result { try runRequest(args: init_.args, methodOverride: nil) }
case "http-get":
    result = Result { try runRequest(args: init_.args, methodOverride: .get) }
case "http-post":
    result = Result { try runRequest(args: init_.args, methodOverride: .post) }
default:
    io.output("Unknown command: \(command)\nExpected: http-request, http-get, http-post\n")
    exit(0)
}

switch result {
case .success(let output):
    io.output(output)
case .failure(let error):
    io.log(level: "error", error.localizedDescription)
    exit(1)
}
