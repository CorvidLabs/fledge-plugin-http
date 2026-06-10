import XCTest
@testable import FledgeHttp

/// Tests for argument parsing, request preparation, header validation,
/// and body handling. All tests are offline -- no sockets, no DNS.
final class RequestBuilderTests: XCTestCase {
    // MARK: - Helpers

    private func args(_ pairs: [(String, String)]) -> [String] {
        pairs.flatMap { ["--\($0.0)", $0.1] }
    }

    // MARK: - Method defaults and override

    func testDefaultsToGET() throws {
        let parsed = parseArgs(args([("url", "https://api.example.com/x")]), declared: declared)
        let req = try prepareRequest(parsed: parsed, methodOverride: nil)
        XCTAssertEqual(req.method, .get)
        XCTAssertNil(req.body)
        XCTAssertFalse(req.allowPrivate)
    }

    func testMethodOverrideWins() throws {
        let parsed = parseArgs(
            args([("url", "https://api.example.com"), ("method", "DELETE")]),
            declared: declared
        )
        // The convenience http-post override beats the explicit method arg.
        let req = try prepareRequest(parsed: parsed, methodOverride: .post)
        XCTAssertEqual(req.method, .post)
    }

    func testExplicitMethodParsed() throws {
        let parsed = parseArgs(
            args([("url", "https://api.example.com"), ("method", "PUT")]),
            declared: declared
        )
        let req = try prepareRequest(parsed: parsed, methodOverride: nil)
        XCTAssertEqual(req.method, .put)
    }

    func testBadMethodThrows() {
        let parsed = parseArgs(
            args([("url", "https://api.example.com"), ("method", "TRACE")]),
            declared: declared
        )
        XCTAssertThrowsError(try prepareRequest(parsed: parsed, methodOverride: nil)) { error in
            XCTAssertTrue("\(error)".contains("not allowed"), "unexpected error: \(error)")
        }
    }

    // MARK: - URL scheme validation

    func testNonHTTPSchemeRejected() {
        let parsed = parseArgs(args([("url", "file:///etc/passwd")]), declared: declared)
        XCTAssertThrowsError(try prepareRequest(parsed: parsed, methodOverride: nil)) { error in
            XCTAssertTrue("\(error)".contains("scheme"), "unexpected error: \(error)")
        }
    }

    func testFTPSchemeRejected() {
        let parsed = parseArgs(args([("url", "ftp://files.example.com/data")]), declared: declared)
        XCTAssertThrowsError(try prepareRequest(parsed: parsed, methodOverride: nil)) { error in
            XCTAssertTrue("\(error)".contains("scheme"), "unexpected error: \(error)")
        }
    }

    func testMissingURLThrows() {
        let parsed = parseArgs(args([("method", "GET")]), declared: declared)
        XCTAssertThrowsError(try prepareRequest(parsed: parsed, methodOverride: nil)) { error in
            XCTAssertTrue("\(error)".contains("url"), "unexpected error: \(error)")
        }
    }

    // MARK: - Bearer auth

    func testBearerSetsAuthorizationHeader() throws {
        let parsed = parseArgs(
            args([("url", "https://api.example.com"), ("bearer", "sekret-token")]),
            declared: declared
        )
        let req = try prepareRequest(parsed: parsed, methodOverride: nil)
        let auth = req.headers.first { $0.name.lowercased() == "authorization" }
        XCTAssertEqual(auth?.value, "Bearer sekret-token")
    }

    func testEmptyBearerThrows() {
        let parsed = parseArgs(
            args([("url", "https://api.example.com"), ("bearer", "")]),
            declared: declared
        )
        XCTAssertThrowsError(try prepareRequest(parsed: parsed, methodOverride: nil))
    }

    // MARK: - Basic auth

    func testBasicAuthBase64() throws {
        let parsed = parseArgs(
            args([
                ("url", "https://api.example.com"),
                ("basic_user", "alice"),
                ("basic_pass", "wonderland"),
            ]),
            declared: declared
        )
        let req = try prepareRequest(parsed: parsed, methodOverride: nil)
        let auth = req.headers.first { $0.name.lowercased() == "authorization" }
        let expected = Data("alice:wonderland".utf8).base64EncodedString()
        XCTAssertEqual(auth?.value, "Basic \(expected)")
    }

    // MARK: - JSON body

    func testJSONBodySetsContentType() throws {
        let parsed = parseArgs(
            args([("url", "https://api.example.com"), ("json", #"{"a":1}"#)]),
            declared: declared
        )
        let req = try prepareRequest(parsed: parsed, methodOverride: .post)
        XCTAssertNotNil(req.body)
        let ct = req.headers.first { $0.name.lowercased() == "content-type" }
        XCTAssertEqual(ct?.value, "application/json")
    }

    func testInvalidJSONBodyThrows() {
        let parsed = parseArgs(
            args([("url", "https://api.example.com"), ("json", "{not json")]),
            declared: declared
        )
        XCTAssertThrowsError(try prepareRequest(parsed: parsed, methodOverride: .post)) { error in
            XCTAssertTrue("\(error)".contains("json body"), "unexpected error: \(error)")
        }
    }

    func testJSONPrecedesRawBody() throws {
        let parsed = parseArgs(
            args([
                ("url", "https://api.example.com"),
                ("json", #"{"k":"v"}"#),
                ("body", "ignored-raw"),
            ]),
            declared: declared
        )
        let req = try prepareRequest(parsed: parsed, methodOverride: .post)
        let bodyString = req.body.flatMap { String(data: $0, encoding: .utf8) }
        XCTAssertEqual(bodyString, #"{"k":"v"}"#)
    }

    func testRawBodyUsedWhenNoJSON() throws {
        let parsed = parseArgs(
            args([
                ("url", "https://api.example.com"),
                ("body", "hello world"),
            ]),
            declared: declared
        )
        let req = try prepareRequest(parsed: parsed, methodOverride: .post)
        let bodyString = req.body.flatMap { String(data: $0, encoding: .utf8) }
        XCTAssertEqual(bodyString, "hello world")
    }

    // MARK: - Query params

    func testQueryParamsAppendedToURL() throws {
        let parsed = parseArgs(
            args([
                ("url", "https://api.example.com/search"),
                ("query", #"{"q":"rust","page":2}"#),
            ]),
            declared: declared
        )
        let req = try prepareRequest(parsed: parsed, methodOverride: nil)
        let query = req.url.query ?? ""
        XCTAssertTrue(query.contains("q=rust"), "query: \(query)")
        XCTAssertTrue(query.contains("page=2"), "query: \(query)")
    }

    // MARK: - allow_private flag

    func testAllowPrivateFlag() throws {
        let parsed = parseArgs(
            args([("url", "http://api.example.com"), ("allow_private", "true")]),
            declared: declared
        )
        let req = try prepareRequest(parsed: parsed, methodOverride: nil)
        XCTAssertTrue(req.allowPrivate)
    }

    func testAllowPrivateFlagFalseByDefault() throws {
        let parsed = parseArgs(
            args([("url", "https://api.example.com")]),
            declared: declared
        )
        let req = try prepareRequest(parsed: parsed, methodOverride: nil)
        XCTAssertFalse(req.allowPrivate)
    }

    // MARK: - Header validation

    func testCRLFInjectionRejected() {
        XCTAssertThrowsError(
            try validateHeader(name: "X-Test", value: "value\r\nX-Injected: evil")
        ) { error in
            XCTAssertTrue("\(error)".contains("control"), "unexpected error: \(error)")
        }
    }

    func testLFInjectionRejected() {
        XCTAssertThrowsError(
            try validateHeader(name: "X-Test", value: "value\nX-Injected: evil")
        )
    }

    func testNULInjectionRejected() {
        XCTAssertThrowsError(
            try validateHeader(name: "X-Test", value: "value\0injected")
        )
    }

    func testEmptyHeaderNameRejected() {
        XCTAssertThrowsError(try validateHeader(name: "", value: "value"))
    }

    func testColonInHeaderNameRejected() {
        XCTAssertThrowsError(try validateHeader(name: "X-Bad:Name", value: "value"))
    }

    func testValidHeaderAccepted() throws {
        XCTAssertNoThrow(try validateHeader(name: "X-Custom-Header", value: "normal value"))
    }

    // MARK: - Secret redaction in header errors

    func testAuthorizationValueRedactedInError() {
        do {
            try validateHeader(name: "Authorization", value: "Bearer top\nsecret")
            XCTFail("Expected throw")
        } catch {
            let msg = "\(error)"
            XCTAssertFalse(msg.contains("top"), "secret leaked in: \(msg)")
            XCTAssertTrue(msg.contains(redacted), "redacted marker missing in: \(msg)")
        }
    }

    // MARK: - Declared args list (mirrored for test access)

    private let declared: [String] = [
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
}
