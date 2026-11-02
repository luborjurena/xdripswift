import CryptoKit
import Foundation
import XCTest
@testable import xdrip

final class OttaiNetSecurityTests: XCTestCase {
    // Independent public synthetic vector from JugglucoNG 11e6e29, generated with Python cryptography.
    private static let vectorJSON = #"""
{
  "deviceId": "ottai:a:n:00000000-0000-0000-0000-000000000001",
  "now": 1793000000000,
  "expires": 1793003600000,
  "exchangeRequest": {
    "clientPubKeyX": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY=",
    "clientPubKeyY": "T+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU=",
    "clientTimestamp": 1793000000000,
    "clientSignature": "7d14940fceee487abae9530db49e97932e183a8b94abe186af599792fbddac2c"
  },
  "exchangeResponse": {
    "code": "OK",
    "data": {
      "serverPubKeyX": "fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI/EdmmXg=",
      "serverPubKeyY": "B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E=",
      "serverTimestamp": 1793000000000,
      "serverSignature": "bffc3608449449f3180d3e9d86091b34679e03f2ce9e614c5d71d3ea9aa41831",
      "expireTime": "1793003600000",
      "secretId": "synthetic-exchange-1",
      "ciphertext": "yE9X61Eg6QeYr1sfng3i7+G8EEiNg8Z/TlliZU8WXfcfBmof3/S/xcl75iwcO9iayAfw0x4NbM9aS7v8PBiMo7BNu+toMzajq3kv1D1yu3vr2B/rN4SdpA==",
      "iv": "AAECAwQFBgcICQoL",
      "authTag": "5mk7Xn9jmGir41SME5r0Qg=="
    }
  },
  "query": {
    "deviceVersion": "E1.1.4(V1.7.S2530.1),STDRD"
  },
  "report": "{\"mac\":\"AABBCCDDEEFF\",\"sourceVersion\":\"E1.1.4(V1.7.S2530.1),STDRD\",\"targetVersion\":\"V1.8.0\",\"upgradeStatus\":1}",
  "get": {
    "headers": {
      "cipherNonceId": "2114621382456250368",
      "cipherTimeNow": "1793000000000",
      "cipherSecretId": "synthetic-exchange-1",
      "cipherUserId": "ottai:a:n:00000000-0000-0000-0000-000000000001",
      "cipherSeq": "1"
    },
    "envelope": {
      "cipherParamText": "j3GzhMD0F1DmWFrRBHbOG1dD9aPLALHOe002viArbIQyZlyOqBmCi3AC9WYa2A==",
      "cipherParamMac": "H/vW8cVenWFgpogBex+vBg==",
      "cipherParamNonce": "EBESExQVFhcYGRob",
      "cipherParamSignature": "siGDFG4bUHledPL8H3k8fnJKMdgVQAUgAI3EUj8La2g="
    }
  },
  "post": {
    "headers": {
      "cipherNonceId": "2114621382456250369",
      "cipherTimeNow": "1793000000000",
      "cipherSecretId": "synthetic-exchange-1",
      "cipherUserId": "ottai:a:n:00000000-0000-0000-0000-000000000001",
      "cipherSeq": "2"
    },
    "envelope": {
      "cipherBodyText": "1y4hIWPGh2k7wv/rlmUyzr/QDL64spnEfcca9wAjyeUIrki8reOfXUCJuCtKdSUI1qlLKZIJfYH9+171YTt0OpDklBD/Mvx0PhlCwIyBtxMGk2dsB0tjaN8xq/BAOFkGD6crwORkg8KWLBo0R54=",
      "cipherBodyMac": "eNnsmrBmPsk26XYvw6QPmw==",
      "cipherBodyNonce": "ICEiIyQlJicoKSor",
      "cipherBodySignature": "wNPPMWpQb0ZtiL3zS7r3omePR25S5odLI7HBZD69gAk="
    }
  },
  "response": {
    "cipherSecretId": "synthetic-exchange-1",
    "cipherText": "7sOd+xbEpLk3IN0Svd8eheQHJHZllIcp55fpJVVjDr0dWat78uXTgDwOCnt5t4BY1KiO88mQYnAL+8wdJ9PQKNK+oA==",
    "cipherMac": "FdG6n0QP/bYGBvG+tSbAdw==",
    "cipherNonce": "MDEyMzQ1Njc4OTo7"
  },
  "plainResponse": {
    "code": "OK",
    "data": {
      "requiredUpgrade": false,
      "allowUpgrade": false
    }
  }
}
"""#
    private var fixture: [String: Any] { try! JSONSerialization.jsonObject(with: Data(Self.vectorJSON.utf8)) as! [String: Any] }
    private func object(_ root: [String: Any], _ key: String) -> [String: Any] { root[key] as! [String: Any] }

    private final class Harness {
        let fixture: [String: Any]
        var time: Int64
        var exchanges = 0, sends = 0, randomCall = 0
        var exchangeReply: [String: Any]
        var reply: [String: Any]
        var status = 200
        var beforeExchange: (([String: Any]) -> OttaiNetSecurity.Reply?)?
        var sent: ((String, String, [String: String], [String: String], String?) throws -> Void)?
        lazy var client = OttaiNetSecurity(owner: fixture["deviceId"] as! String, exchange: { request in
            self.exchanges += 1
            if let override = self.beforeExchange?(request) { return override }
            return .init(status: 200, json: self.exchangeReply)
        }, send: { method, path, headers, query, body in
            self.sends += 1
            try self.sent?(method, path, headers, query, body)
            return .init(status: self.status, json: self.reply)
        }, clock: { self.time }, keyPair: {
            try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 0, count: 31) + Data([1]))
        }, randomBytes: { count in
            self.randomCall += 1
            return Data((0..<count).map { UInt8(self.randomCall * 16 + $0) })
        })
        init(_ fixture: [String: Any]) {
            self.fixture = fixture
            time = (fixture["now"] as! NSNumber).int64Value
            exchangeReply = fixture["exchangeResponse"] as! [String: Any]
            reply = fixture["response"] as! [String: Any]
        }
        func get() throws -> OttaiNetSecurity.Reply {
            try client.request(method: "GET", path: "/ota/upgradeVersion/judge", query: fixture["query"] as! [String: String])
        }
    }

    func testIndependentFixedExchangeQueryBodyAndResponseVectors() throws {
        let f = fixture, h = Harness(f)
        h.beforeExchange = { request in
            XCTAssertEqual(try! OttaiNetSecurity.jsonString(request), try! OttaiNetSecurity.jsonString(f["exchangeRequest"]!))
            return nil
        }
        h.sent = { method, _, headers, query, body in
            XCTAssertEqual(method, "GET")
            var expected = self.object(f, "get")["headers"] as! [String: String]
            expected["webDeviceId"] = expected.removeValue(forKey: "cipherUserId")
            XCTAssertEqual(headers, expected)
            XCTAssertEqual(query, self.object(f, "get")["envelope"] as! [String: String])
            XCTAssertNil(body)
        }
        XCTAssertEqual(try OttaiNetSecurity.jsonString(h.get().json!), try OttaiNetSecurity.jsonString(f["plainResponse"]!))
        h.sent = { method, _, headers, query, body in
            XCTAssertEqual(method, "POST")
            XCTAssertEqual(headers["cipherSeq"], "2")
            XCTAssertTrue(query.isEmpty)
            let envelope = try JSONSerialization.jsonObject(with: Data(XCTUnwrap(body).utf8)) as! [String: String]
            XCTAssertEqual(envelope, self.object(f, "post")["envelope"] as! [String: String])
        }
        _ = try h.client.request(method: "POST", path: "/device/ota/upgrade", body: f["report"] as? String)
        XCTAssertEqual(h.exchanges, 1)
        XCTAssertEqual(h.sends, 2)
    }

    func testInvalidExchangeSignatureAndAuthenticationNeverSend() {
        for field in ["serverSignature", "authTag", "serverPubKeyX"] {
            let h = Harness(fixture)
            var data = h.exchangeReply["data"] as! [String: Any]
            data[field] = "invalid"
            h.exchangeReply["data"] = data
            XCTAssertThrowsError(try h.get())
            XCTAssertEqual(h.sends, 0)
        }
    }

    func testResponseAuthenticationIdentityAndPlaintextSuccessFailClosed() {
        for field in ["cipherMac", "cipherSecretId", "cipherNonce"] {
            let h = Harness(fixture); h.reply[field] = "invalid"
            XCTAssertThrowsError(try h.get())
        }
        let h = Harness(fixture)
        h.reply = ["code": "OK", "data": ["accessToken": "synthetic-should-not-be-used"]]
        XCTAssertThrowsError(try h.get())
    }

    func testExpiredSecretCannotBeReusedAndCloseRequiresNewExchange() throws {
        let h = Harness(fixture)
        _ = try h.get()
        h.client.close()
        _ = try h.get()
        XCTAssertEqual(h.exchanges, 2)
        h.time = (fixture["expires"] as! NSNumber).int64Value + 1
        XCTAssertThrowsError(try h.get())
        XCTAssertEqual(h.exchanges, 3)
        XCTAssertEqual(h.sends, 2)
    }

    func testClockOffsetCorrectionIsBounded() throws {
        let h = Harness(fixture), now = (fixture["now"] as! NSNumber).int64Value
        h.time = now - 10_000
        h.beforeExchange = { request in
            if h.exchanges == 1 { return .init(status: 200, json: ["code": "CLIENT_CLOCK_OFFSET", "currentTime": now]) }
            XCTAssertEqual((request["clientTimestamp"] as! NSNumber).int64Value, now)
            return nil
        }
        _ = try h.get()
        XCTAssertEqual(h.exchanges, 2)
        let endless = Harness(fixture)
        endless.beforeExchange = { _ in .init(status: 200, json: ["code": "CLIENT_CLOCK_OFFSET", "currentTime": now]) }
        XCTAssertThrowsError(try endless.get())
        XCTAssertEqual(endless.exchanges, 2)
        XCTAssertEqual(endless.sends, 0)
    }

    func testEmptyResponseAndTransportFailureDoNotRetry() {
        let h = Harness(fixture)
        h.sent = { _, _, _, _, _ in throw OttaiSecureTransportFailure(diagnostic: "synthetic_network_failure") }
        XCTAssertThrowsError(try h.get())
        XCTAssertEqual(h.exchanges, 1)
        XCTAssertEqual(h.sends, 1)
        let empty = OttaiNetSecurity(owner: "synthetic", exchange: { _ in .init(status: 200, json: nil) }, send: { _, _, _, _, _ in XCTFail(); return .init(status: 200, json: nil) })
        XCTAssertThrowsError(try empty.request(method: "GET", path: "/user/apiToken"))
    }
}
