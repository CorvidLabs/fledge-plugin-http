import XCTest
@testable import FledgeHttp

/// Tests for the error-message redaction logic.
final class RedactionTests: XCTestCase {
    func testRedactsBearerToken() {
        let msg = "request to https://x with Bearer abc123def failed: timeout"
        let out = redactError(msg)
        XCTAssertFalse(out.contains("abc123def"), "token leaked: \(out)")
        XCTAssertTrue(out.contains(redacted), "redacted marker missing: \(out)")
    }

    func testRedactsBasicCredentials() {
        let msg = "auth Basic YWxpY2U6d29uZGVybGFuZA== rejected"
        let out = redactError(msg)
        XCTAssertFalse(out.contains("YWxpY2U6d29uZGVybGFuZA=="), "credentials leaked: \(out)")
        XCTAssertTrue(out.contains(redacted), "redacted marker missing: \(out)")
    }

    func testPassthroughWhenNoSecret() {
        let msg = "connection refused by upstream"
        XCTAssertEqual(redactError(msg), msg)
    }

    func testPreservesTextAroundToken() {
        let msg = "failed: Bearer secret123 at step 2"
        let out = redactError(msg)
        XCTAssertTrue(out.hasPrefix("failed: Bearer "), "prefix lost: \(out)")
        XCTAssertTrue(out.hasSuffix(" at step 2"), "suffix lost: \(out)")
        XCTAssertFalse(out.contains("secret123"), "token leaked: \(out)")
    }

    func testMultipleSecretsRedacted() {
        let msg = "Bearer tok1 and Basic Y2Fw then Bearer tok2"
        let out = redactError(msg)
        XCTAssertFalse(out.contains("tok1"), "tok1 leaked: \(out)")
        XCTAssertFalse(out.contains("Y2Fw"), "basic creds leaked: \(out)")
        XCTAssertFalse(out.contains("tok2"), "tok2 leaked: \(out)")
    }
}
