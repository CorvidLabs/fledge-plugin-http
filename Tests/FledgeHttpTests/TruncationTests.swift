import XCTest
@testable import FledgeHttp

/// Tests for body-cap truncation behavior.
final class TruncationTests: XCTestCase {
    func testShortBodyNotTruncated() {
        let text = "hello world"
        let (result, wasTruncated) = truncateAtCharBoundary(text, maxBytes: 100)
        XCTAssertEqual(result, text)
        XCTAssertFalse(wasTruncated)
    }

    func testExactSizeNotTruncated() {
        let text = String(repeating: "a", count: maxBodyBytes)
        let (_, wasTruncated) = truncateAtCharBoundary(text, maxBytes: maxBodyBytes)
        XCTAssertFalse(wasTruncated)
    }

    func testOversizedBodyTruncated() {
        let text = String(repeating: "a", count: maxBodyBytes + 10)
        let (result, wasTruncated) = truncateAtCharBoundary(text, maxBytes: maxBodyBytes)
        XCTAssertTrue(wasTruncated)
        XCTAssertLessThanOrEqual(result.utf8.count, maxBodyBytes)
    }

    func testTruncationOnCharBoundary() {
        // Build a string that contains multi-byte UTF-8 characters (2 bytes each for
        // the accented characters) and is large enough to need truncation.
        let unit = "he\u{0301}llo-"  // combining accent = 2 bytes for the combining mark
        let big = String(repeating: unit, count: (maxBodyBytes / unit.utf8.count) + 10)
        XCTAssertGreaterThan(big.utf8.count, maxBodyBytes)
        let (result, wasTruncated) = truncateAtCharBoundary(big, maxBytes: maxBodyBytes)
        XCTAssertTrue(wasTruncated)
        XCTAssertLessThanOrEqual(result.utf8.count, maxBodyBytes)
        // The cut must be valid UTF-8 -- round-tripping through Data must succeed.
        let roundTripped = String(data: Data(result.utf8), encoding: .utf8)
        XCTAssertNotNil(roundTripped, "truncated result is not valid UTF-8")
        XCTAssertEqual(roundTripped, result)
    }

    func testTruncationPreservesValidUTF8() {
        // A string with 3-byte characters (CJK block).
        let unit = "\u{4e2d}\u{6587}"  // "Chinese" -- each char is 3 bytes
        let big = String(repeating: unit, count: (maxBodyBytes / (unit.utf8.count)) + 5)
        XCTAssertGreaterThan(big.utf8.count, maxBodyBytes)
        let (result, wasTruncated) = truncateAtCharBoundary(big, maxBytes: maxBodyBytes)
        XCTAssertTrue(wasTruncated)
        XCTAssertLessThanOrEqual(result.utf8.count, maxBodyBytes)
        XCTAssertNotNil(String(data: Data(result.utf8), encoding: .utf8))
    }
}
