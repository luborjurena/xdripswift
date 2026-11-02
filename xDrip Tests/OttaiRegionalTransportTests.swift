import CryptoKit
import Foundation
import XCTest
@testable import xdrip

final class OttaiRegionalTransportTests: XCTestCase {
    private let headers = ["deviceId": "ottai-watch:a:synthetic-install", "appName": "ottai-watch", "packageName": "com.ottai.tag.watch", "timestamp": "1793000000123", "Authorization": "synthetic-account", "versionName": "1.1.0", "versionCode": "244301"]
    private let origin = "https://seas.ottai.com/cgm/app/server"

    /// Synthetic server independently derives ECDH keys and authenticates the production HTTP request.
    private final class Server {
        var exchanges = 0, applications = 0
        var owners: [String] = [], clientKeys: [String] = []
        var urls: [String] = [], methods: [String] = []
        var received: [[String: Any]] = [], allHeaders: [[String: String]] = []
        var responseBody: [String: Any] = ["code": "OK", "data": ["mac": "AABBCCDDEEFF"]]
        var businessStatus = 200
        var plaintextResponse = false
        var failExchange = false, failRequest = false
        var key: SymmetricKey!, signing: SymmetricKey!
        var secret = "", owner = ""
        var sawEncodedPlus = false

        func send(_ method: String, _ url: String, _ body: String?, _ headers: [String: String]) throws -> OttaiNetSecurity.Reply {
            urls.append(url); allHeaders.append(headers)
            let parts = try XCTUnwrap(URLComponents(string: url))
            if parts.path.hasSuffix("/security/exchangeKey") {
                exchanges += 1
                if failExchange { throw OttaiSecureTransportFailure(diagnostic: "synthetic-network") }
                owner = try XCTUnwrap(headers["webDeviceId"])
                owners.append(owner)
                let request = try JSONSerialization.jsonObject(with: Data(XCTUnwrap(body).utf8)) as! [String: Any]
                let x = request["clientPubKeyX"] as! String, y = request["clientPubKeyY"] as! String
                clientKeys.append(x + y)
                let timestamp = OttaiNetSecurity.string(request["clientTimestamp"])
                XCTAssertEqual(request["clientSignature"] as? String, Self.hash(owner + x + y + timestamp))
                let server = P256.KeyAgreement.PrivateKey()
                let raw = server.publicKey.rawRepresentation
                let sx = raw.prefix(32).base64EncodedString(), sy = raw.suffix(32).base64EncodedString()
                let publicKey = try P256.KeyAgreement.PublicKey(rawRepresentation: XCTUnwrap(Data(base64Encoded: x)) + XCTUnwrap(Data(base64Encoded: y)))
                let shared = try server.sharedSecretFromKeyAgreement(with: publicKey)
                secret = "synthetic-channel-\(exchanges)"
                let expiry = String(Int64(timestamp)! + 3_600_000)
                let keys = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(secret.utf8), sharedInfo: Data((owner + "#" + expiry + "#" + secret).utf8), outputByteCount: 64)
                keys.withUnsafeBytes { self.key = SymmetricKey(data: $0.prefix(32)); self.signing = SymmetricKey(data: $0.suffix(32)) }
                let box = try AES.GCM.seal(Data((sx + sy).utf8), using: key, authenticating: Data((owner + "|" + secret).utf8))
                return .init(status: 200, json: ["code": "OK", "data": ["serverPubKeyX": sx, "serverPubKeyY": sy, "serverTimestamp": timestamp, "serverSignature": Self.hash(owner + sx + sy + timestamp), "secretId": secret, "expireTime": expiry, "ciphertext": box.ciphertext.base64EncodedString(), "iv": Data(box.nonce).base64EncodedString(), "authTag": box.tag.base64EncodedString()]])
            }
            applications += 1; methods.append(method)
            if failRequest { throw OttaiSecureTransportFailure(diagnostic: "synthetic-network") }
            XCTAssertEqual(headers["cipherSecretId"], secret)
            XCTAssertEqual(headers["cipherSeq"], "1", "A new HTTP operation owns a fresh channel")
            var envelope: [String: String] = [:]
            let kind: String
            if let body {
                kind = "Body"
                envelope = try JSONSerialization.jsonObject(with: Data(body.utf8)) as! [String: String]
            } else {
                kind = "Param"
                let encoded = parts.percentEncodedQuery ?? ""
                XCTAssertFalse(encoded.contains("+"), "Base64 '+' must survive a form-decoding server")
                sawEncodedPlus = sawEncodedPlus || encoded.contains("%2B")
                for field in encoded.split(separator: "&") {
                    let pair = field.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                    let name = pair[0].replacingOccurrences(of: "+", with: " ").removingPercentEncoding!
                    let value = pair[1].replacingOccurrences(of: "+", with: " ").removingPercentEncoding!
                    envelope[name] = value
                }
            }
            if !envelope.isEmpty {
                let text = try XCTUnwrap(envelope["cipher\(kind)Text"])
                let signed = try XCTUnwrap(headers["cipherNonceId"]) + XCTUnwrap(headers["cipherSeq"]) + XCTUnwrap(headers["cipherTimeNow"]) + text
                let signature = try XCTUnwrap(Data(base64Encoded: XCTUnwrap(envelope["cipher\(kind)Signature"])))
                XCTAssertTrue(HMAC<SHA256>.isValidAuthenticationCode(signature, authenticating: Data(signed.utf8), using: signing))
                let nonce = try AES.GCM.Nonce(data: XCTUnwrap(Data(base64Encoded: XCTUnwrap(envelope["cipher\(kind)Nonce"]))))
                let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: XCTUnwrap(Data(base64Encoded: text)), tag: XCTUnwrap(Data(base64Encoded: XCTUnwrap(envelope["cipher\(kind)Mac"]))))
                let plain = try AES.GCM.open(box, using: key, authenticating: Data((owner + "|" + secret).utf8))
                received.append(try JSONSerialization.jsonObject(with: plain) as! [String: Any])
            } else { received.append([:]) }
            if businessStatus != 200 || plaintextResponse { return .init(status: businessStatus, json: responseBody) }
            let box = try AES.GCM.seal(JSONSerialization.data(withJSONObject: responseBody), using: key, authenticating: Data((owner + "|" + secret).utf8))
            return .init(status: 200, json: ["cipherSecretId": secret, "cipherText": box.ciphertext.base64EncodedString(), "cipherMac": box.tag.base64EncodedString(), "cipherNonce": Data(box.nonce).base64EncodedString()])
        }
        static func hash(_ text: String) -> String { SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined() }
    }

    func testProductionDispatcherEncryptsGETPOSTPUTAndPreservesIdentityAndSignedTimestamp() throws {
        let server = Server()
        let payload = "{\"account\":\"synthetic\",\"password\":\"synthetic-password\",\"signature\":\"already-signed\"}"
        for verb in ["GET", "POST", "PUT"] {
            let reply = try OttaiRegionalTransport.request(verb, url: origin + "/user/accountLogin" + (verb == "GET" ? "?value=a%2Bb%2Fc%3D%3D&space=a+b" : ""), body: verb == "GET" ? nil : payload, headers: headers, send: server.send)
            XCTAssertEqual(reply.json?["code"] as? String, "OK")
        }
        XCTAssertEqual(server.exchanges, 3)
        XCTAssertEqual(server.applications, 3)
        XCTAssertEqual(Set(server.clientKeys).count, 3)
        XCTAssertTrue(server.urls.allSatisfy { $0.hasPrefix("https://seas.ottai.com/cgm/security/app/server/") })
        for h in server.allHeaders {
            XCTAssertEqual(h["deviceId"], headers["deviceId"])
            XCTAssertEqual(h["webDeviceId"], headers["deviceId"])
            XCTAssertEqual(h["Authorization"], headers["Authorization"])
            XCTAssertEqual(h["timestamp"], headers["timestamp"])
            XCTAssertEqual(h["versionName"], "1.1.0")
            XCTAssertEqual(h["versionCode"], "10000000")
            XCTAssertNil(h["X-Forwarded-For"])
        }
        XCTAssertEqual(server.received[0]["value"] as? String, "a+b/c==")
        XCTAssertEqual(server.received[0]["space"] as? String, "a b")
        XCTAssertEqual(server.received[1]["signature"] as? String, "already-signed")
        XCTAssertEqual(server.received[2]["password"] as? String, "synthetic-password")
    }

    func testBase64QuerySurvivesFormDecoding() throws {
        let server = Server()
        for _ in 0..<8 {
            _ = try OttaiRegionalTransport.request("GET", url: origin + "/user/apiToken?signature=" + String(repeating: "x", count: 200), body: nil, headers: headers, send: server.send)
        }
        XCTAssertTrue(server.sawEncodedPlus)
        XCTAssertTrue(server.received.allSatisfy { ($0["signature"] as? String)?.count == 200 })
    }

    func testAuthenticatedAndPreDecryptionBusinessErrorsCannotSupplyCredentialsOrRetry() throws {
        for status in [200, 401] {
            let server = Server(); server.businessStatus = status
            server.responseBody = ["code": "AuthFailed_TokenInvalid", "message": "private-message", "data": ["accessToken": "synthetic-unusable"]]
            let reply = try OttaiRegionalTransport.request("GET", url: origin + "/user/getUser", body: nil, headers: headers, send: server.send)
            XCTAssertEqual(reply.json?["code"] as? String, "AuthFailed_TokenInvalid")
            XCTAssertNil(reply.json?["data"])
            if status == 200 {
                XCTAssertEqual(reply.origin, .authenticated)
                XCTAssertEqual(reply.json?["message"] as? String, "private-message")
            } else {
                XCTAssertEqual(reply.origin, .gateway)
                XCTAssertNil(reply.json?["message"])
            }
            XCTAssertEqual(server.applications, 1)
        }
    }

    func testNetworkFailuresAndPlaintextSuccessNeverFallBack() {
        for phase in 0..<3 {
            let server = Server(); server.failExchange = phase == 0; server.failRequest = phase == 1; server.plaintextResponse = phase == 2
            XCTAssertThrowsError(try OttaiRegionalTransport.request("POST", url: origin + "/user/accountLogin", body: "{}", headers: headers, send: server.send))
            XCTAssertEqual(server.exchanges, 1)
            XCTAssertEqual(server.applications, phase == 0 ? 0 : 1)
            XCTAssertTrue(server.urls.allSatisfy { $0.contains("/cgm/security/app/server/") })
        }
    }

    func testOtherRegionsAndWebKeepTheirExistingTransportAndUnsafeGlobalURLsFail() throws {
        for url in ["https://api.ottai.com/cgm/app/server/user/apiToken", "https://api.syai.com/cgm/app/server/user/apiToken", "https://www.ottai.com/api/cgm/web/user/getUser"] {
            var calls = 0
            _ = try OttaiRegionalTransport.request("GET", url: url, body: nil, headers: headers) { _, target, _, h in
                calls += 1; XCTAssertEqual(target, url); XCTAssertEqual(h, self.headers)
                return .init(status: 200, json: ["code": "OK"])
            }
            XCTAssertEqual(calls, 1)
        }
        for url in ["http://seas.ottai.com/cgm/app/server/user/getUser", "https://seas.ottai.com:443/cgm/app/server/user/getUser", "https://user@seas.ottai.com/cgm/app/server/user/getUser", origin + "/../getUser", origin + "/user/getUser#fragment"] {
            XCTAssertThrowsError(try OttaiRegionalTransport.route(url))
        }
    }
    func testSecureHTTPRejectsWrongTargetsAndRefusesRedirects() throws {
        for target in ["https://other.invalid/cgm/security/app/server/user/apiToken", "http://seas.ottai.com/cgm/security/app/server/user/apiToken", "https://seas.ottai.com/cgm/app/server/user/apiToken"] {
            XCTAssertThrowsError(try OttaiSecureHTTP.send("GET", url: target, body: nil, headers: [:]))
        }
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let url = URL(string: "https://seas.ottai.com/cgm/security/app/server/user/apiToken")!
        let task = session.dataTask(with: url) // Intentionally never resumed: this is a delegate contract test.
        let response = HTTPURLResponse(url: url, statusCode: 302, httpVersion: nil, headerFields: ["Location": "https://other.invalid"])!
        var called = false
        OttaiSecureHTTP.NoRedirect().urlSession(session, task: task, willPerformHTTPRedirection: response, newRequest: URLRequest(url: URL(string: "https://other.invalid")!)) { forwarded in
            called = true
            XCTAssertNil(forwarded)
        }
        XCTAssertTrue(called)
    }

    func testAuthenticatedUnknownKeepsSanitizedReasonWithoutCredentials() throws {
        let server = Server()
        server.responseBody = ["code": "unknown", "message": "Account synthetic-user rejected; password=synthetic-password https://private.invalid/path?token=longsecret", "data": ["accessToken": "synthetic-token"]]
        let reply = try OttaiRegionalTransport.request("POST", url: origin + "/user/accountLogin", body: "{\"account\":\"synthetic-user\",\"password\":\"synthetic-password\"}", headers: headers, send: server.send)
        XCTAssertEqual(reply.origin, .authenticated)
        XCTAssertEqual(reply.json?["code"] as? String, "unknown")
        XCTAssertNil(reply.json?["data"])
        let message = try XCTUnwrap(reply.json?["message"] as? String)
        XCTAssertTrue(message.contains("rejected"))
        XCTAssertFalse(message.contains("synthetic-user"))
        XCTAssertFalse(message.contains("synthetic-password"))
        XCTAssertFalse(message.contains("private.invalid"))
        XCTAssertFalse(message.contains("longsecret"))
    }

    func testErrorMessageSanitizerIsBoundedAndRemovesShortKnownSecrets() {
        let message = OttaiRegionalTransport.sanitizedMessage("mail test@example.invalid password=123 token=secret\n" + String(repeating: "detail ", count: 100), redacting: ["123"])
        XCTAssertLessThanOrEqual(message.count, 240)
        XCTAssertFalse(message.contains("example.invalid"))
        XCTAssertFalse(message.contains("123"))
        XCTAssertFalse(message.contains("secret"))
        XCTAssertFalse(message.contains("\n"))
    }

}
