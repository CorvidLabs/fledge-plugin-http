import XCTest
@testable import FledgeHttp

/// Tests for the SSRF guard's IP classification logic.
///
/// All cases are offline (no real DNS, no sockets): we test the pure
/// `isPublicIP` predicate and the `parseIPv4`/`parseIPv6` helpers directly.
final class SSRFGuardTests: XCTestCase {
    // MARK: - Public IPv4

    func testPublicIPv4Accepted() {
        let publicAddresses = ["1.1.1.1", "8.8.8.8", "151.101.0.81", "93.184.216.34"]
        for addr in publicAddresses {
            XCTAssertTrue(SSRFGuard.isPublicIP(addr), "\(addr) should be accepted as public")
        }
    }

    // MARK: - Private / blocked IPv4

    func testLoopbackRejected() {
        XCTAssertFalse(SSRFGuard.isPublicIP("127.0.0.1"))
        XCTAssertFalse(SSRFGuard.isPublicIP("127.255.255.255"))
    }

    func testUnspecifiedRejected() {
        XCTAssertFalse(SSRFGuard.isPublicIP("0.0.0.0"))
    }

    func testPrivateClassARejected() {
        XCTAssertFalse(SSRFGuard.isPublicIP("10.0.0.1"))
        XCTAssertFalse(SSRFGuard.isPublicIP("10.255.255.255"))
    }

    func testPrivateClassBRejected() {
        XCTAssertFalse(SSRFGuard.isPublicIP("172.16.0.1"))
        XCTAssertFalse(SSRFGuard.isPublicIP("172.31.255.255"))
    }

    func testPrivateClassCRejected() {
        XCTAssertFalse(SSRFGuard.isPublicIP("192.168.0.1"))
        XCTAssertFalse(SSRFGuard.isPublicIP("192.168.255.255"))
    }

    func testLinkLocalRejected() {
        // Covers the cloud-metadata address 169.254.169.254.
        XCTAssertFalse(SSRFGuard.isPublicIP("169.254.0.1"))
        XCTAssertFalse(SSRFGuard.isPublicIP("169.254.169.254"))
        XCTAssertFalse(SSRFGuard.isPublicIP("169.254.255.255"))
    }

    func testCarrierGradeNATRejected() {
        XCTAssertFalse(SSRFGuard.isPublicIP("100.64.0.1"))
        XCTAssertFalse(SSRFGuard.isPublicIP("100.127.255.255"))
    }

    func testMulticastRejected() {
        XCTAssertFalse(SSRFGuard.isPublicIP("224.0.0.1"))
        XCTAssertFalse(SSRFGuard.isPublicIP("239.255.255.255"))
    }

    func testBroadcastRejected() {
        XCTAssertFalse(SSRFGuard.isPublicIP("255.255.255.255"))
    }

    // MARK: - Public IPv6

    func testPublicIPv6Accepted() {
        let publicAddresses = ["2606:4700:4700::1111", "2001:4860:4860::8888"]
        for addr in publicAddresses {
            XCTAssertTrue(SSRFGuard.isPublicIP(addr), "\(addr) should be accepted")
        }
    }

    // MARK: - Private / blocked IPv6

    func testIPv6LoopbackRejected() {
        XCTAssertFalse(SSRFGuard.isPublicIP("::1"))
    }

    func testIPv6UnspecifiedRejected() {
        XCTAssertFalse(SSRFGuard.isPublicIP("::"))
    }

    func testULARejected() {
        XCTAssertFalse(SSRFGuard.isPublicIP("fc00::1"))
        XCTAssertFalse(SSRFGuard.isPublicIP("fd12:3456::1"))
    }

    func testIPv6LinkLocalRejected() {
        XCTAssertFalse(SSRFGuard.isPublicIP("fe80::1"))
    }

    func testIPv6MulticastRejected() {
        XCTAssertFalse(SSRFGuard.isPublicIP("ff02::1"))
    }

    // MARK: - IPv4-mapped IPv6 bypass

    func testIPv4MappedLoopbackRejected() {
        // ::ffff:127.0.0.1 must not bypass the IPv4 guard.
        XCTAssertFalse(SSRFGuard.isPublicIP("::ffff:127.0.0.1"))
    }

    func testIPv4MappedMetadataRejected() {
        // ::ffff:169.254.169.254 is the cloud metadata address in IPv4-mapped form.
        XCTAssertFalse(SSRFGuard.isPublicIP("::ffff:169.254.169.254"))
    }

    func testIPv4MappedPrivateRejected() {
        XCTAssertFalse(SSRFGuard.isPublicIP("::ffff:192.168.1.1"))
        XCTAssertFalse(SSRFGuard.isPublicIP("::ffff:10.0.0.1"))
    }

    func testIPv4MappedPublicAccepted() {
        XCTAssertTrue(SSRFGuard.isPublicIP("::ffff:1.1.1.1"))
    }

    // MARK: - Parser round-trips

    func testParseIPv4ValidAddress() {
        let result = SSRFGuard.parseIPv4("192.168.1.100")
        XCTAssertEqual(result?.0, 192)
        XCTAssertEqual(result?.1, 168)
        XCTAssertEqual(result?.2, 1)
        XCTAssertEqual(result?.3, 100)
    }

    func testParseIPv4RejectsInvalidInput() {
        XCTAssertNil(SSRFGuard.parseIPv4("not-an-ip"))
        XCTAssertNil(SSRFGuard.parseIPv4("256.0.0.1"))
        XCTAssertNil(SSRFGuard.parseIPv4("1.2.3"))
    }

    func testParseIPv6LoopbackSegments() {
        let segs = SSRFGuard.parseIPv6("::1")
        XCTAssertEqual(segs?.count, 8)
        XCTAssertEqual(segs?.last, 1)
        XCTAssertEqual(segs?.dropLast().allSatisfy { $0 == 0 }, true)
    }

    func testParseIPv6FullAddress() {
        let segs = SSRFGuard.parseIPv6("2606:4700:4700:0000:0000:0000:0000:1111")
        XCTAssertEqual(segs?.count, 8)
        XCTAssertEqual(segs?.first, 0x2606)
    }
}
