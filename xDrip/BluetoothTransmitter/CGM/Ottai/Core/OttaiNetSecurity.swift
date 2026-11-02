// SPDX-License-Identifier: GPL-3.0-or-later
// Port of ctqvva/JugglucoNG 11e6e29db7d9055c8fd2e96261812e16f2095f3d,
// OttaiNetSecurity.kt. No account data, plaintext or key material is logged.
import CryptoKit
import Foundation
import Security

struct OttaiSecureTransportFailure: Error {
    let diagnostic: String
    var businessCode = ""
    var httpStatus = 0
}

final class OttaiNetSecurity {
    enum ResponseOrigin: String { case direct, gateway, authenticated }
    struct Reply {
        let status: Int
        let json: [String: Any]?
        let origin: ResponseOrigin
        init(status: Int, json: [String: Any]?, origin: ResponseOrigin = .direct) {
            self.status = status; self.json = json; self.origin = origin
        }
    }
    typealias Sender = (String, String, [String: String], [String: String], String?) throws -> Reply
    private struct Secret {
        let id: String
        let expires: Int64
        let aes: SymmetricKey
        let signing: SymmetricKey
        var sequence: Int64 = 0
    }
    private let owner: String
    private let exchange: ([String: Any]) throws -> Reply
    private let send: Sender
    private let clock: () -> Int64
    private let keyPair: () throws -> P256.KeyAgreement.PrivateKey
    private let randomBytes: (Int) throws -> Data
    private var secret: Secret?
    private var clockOffset: Int64 = 0
    private var lastNonce: Int64 = 0

    init(owner: String, exchange: @escaping ([String: Any]) throws -> Reply, send: @escaping Sender,
         clock: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) },
         keyPair: @escaping () throws -> P256.KeyAgreement.PrivateKey = { P256.KeyAgreement.PrivateKey() },
         randomBytes: @escaping (Int) throws -> Data = OttaiNetSecurity.random) {
        self.owner = owner; self.exchange = exchange; self.send = send
        self.clock = clock; self.keyPair = keyPair; self.randomBytes = randomBytes
    }

    /// The production router creates one instance per HTTP operation and releases all keys here.
    func close() { secret = nil }

    func request(method: String, path: String, query: [String: String] = [:], body: String? = nil) throws -> Reply {
        guard ["GET", "POST", "PUT"].contains(method), path.hasPrefix("/"), !path.contains(".."), !path.contains("?") else {
            throw failure("secure_request_shape")
        }
        if secret == nil || secret!.expires <= now() { close(); secret = try establish() }
        guard var current = secret else { throw failure("secure_exchange_crypto") }
        let time = now()
        let shifted = (time - 1_288_834_974_657) &<< 22
        let nonceNumber = max(shifted | 4096, lastNonce &+ 1)
        guard nonceNumber > 0 else { throw failure("secure_clock") }
        lastNonce = nonceNumber
        current.sequence += 1
        secret = current
        let nonceID = String(nonceNumber), sequence = String(current.sequence)
        let headers = ["cipherNonceId": nonceID, "cipherTimeNow": String(time), "cipherSecretId": current.id,
                       "webDeviceId": owner, "cipherSeq": sequence]
        func envelope(_ plain: String, kind: String) throws -> [String: String] {
            let nonceData = try randomBytes(12)
            guard nonceData.count == 12 else { throw failure("secure_random") }
            let sealed = try AES.GCM.seal(Data(plain.utf8), using: current.aes,
                                          nonce: AES.GCM.Nonce(data: nonceData), authenticating: aad(current.id))
            let text = sealed.ciphertext.base64EncodedString()
            let signature = HMAC<SHA256>.authenticationCode(for: Data((nonceID + sequence + String(time) + text).utf8), using: current.signing)
            return ["cipher\(kind)Text": text, "cipher\(kind)Mac": sealed.tag.base64EncodedString(),
                    "cipher\(kind)Nonce": nonceData.base64EncodedString(), "cipher\(kind)Signature": Data(signature).base64EncodedString()]
        }
        let encryptedQuery = query.isEmpty ? [:] : try envelope(Self.jsonString(query), kind: "Param")
        let encryptedBody = try body.map { try Self.jsonString(envelope($0, kind: "Body")) }
        let reply = try send(method, path, headers, encryptedQuery, encryptedBody)
        guard let outer = reply.json else { throw failure("secure_request_empty", status: reply.status) }
        // Gateway failures are not credentials, and the router removes their data before returning.
        guard Self.successful(reply) else { return Reply(status: reply.status, json: reply.json, origin: .gateway) }
        do {
            guard Self.string(outer["cipherSecretId"]) == current.id else { throw failure("secure_response_cipher") }
            let plaintext = try open(outer, text: "cipherText", nonce: "cipherNonce", tag: "cipherMac", secret: current)
            guard let decoded = try JSONSerialization.jsonObject(with: plaintext) as? [String: Any] else { throw failure("secure_response_cipher") }
            return Reply(status: reply.status, json: decoded, origin: .authenticated)
        } catch { throw failure("secure_response_cipher") }
    }

    private func establish() throws -> Secret {
        let pair = try keyPair()
        let raw = pair.publicKey.rawRepresentation
        let x = raw.prefix(32).base64EncodedString(), y = raw.suffix(32).base64EncodedString()
        var result: [String: Any]?
        for attempt in 0..<2 {
            let time = now()
            let reply = try exchange(["clientPubKeyX": x, "clientPubKeyY": y, "clientTimestamp": time,
                                      "clientSignature": Self.sha256(owner + x + y + String(time))])
            if attempt == 0, Self.string(reply.json?["code"]) == "CLIENT_CLOCK_OFFSET",
               let serverTime = Int64(Self.string(reply.json?["currentTime"])), serverTime > 0 {
                clockOffset = serverTime - clock()
                continue
            }
            guard Self.successful(reply) else {
                throw failure("secure_exchange", code: Self.safeCode(reply.json?["code"]), status: reply.status)
            }
            result = reply.json?["data"] as? [String: Any]
            break
        }
        guard let result else { throw failure("secure_exchange_response") }
        do {
            let sx = Self.string(result["serverPubKeyX"]), sy = Self.string(result["serverPubKeyY"])
            let time = Self.string(result["serverTimestamp"])
            guard Self.sha256(owner + sx + sy + time) == Self.string(result["serverSignature"]).lowercased(),
                  let xData = Data(base64Encoded: sx), xData.count == 32,
                  let yData = Data(base64Encoded: sy), yData.count == 32 else { throw failure("secure_exchange_crypto") }
            let id = Self.string(result["secretId"]), expiryString = Self.string(result["expireTime"])
            guard !id.isEmpty, id.count <= 256, let expiry = Int64(expiryString), expiry > now() else { throw failure("secure_exchange_crypto") }
            let publicKey = try P256.KeyAgreement.PublicKey(rawRepresentation: xData + yData)
            let shared = try pair.sharedSecretFromKeyAgreement(with: publicKey)
            let derived = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(id.utf8),
                sharedInfo: Data((owner + "#" + expiryString + "#" + id).utf8), outputByteCount: 64)
            let current: Secret = derived.withUnsafeBytes {
                Secret(id: id, expires: expiry, aes: SymmetricKey(data: $0.prefix(32)), signing: SymmetricKey(data: $0.suffix(32)))
            }
            let confirmation = try open(result, text: "ciphertext", nonce: "iv", tag: "authTag", secret: current)
            guard confirmation == Data((sx + sy).utf8) else { throw failure("secure_exchange_crypto") }
            return current
        } catch { throw failure("secure_exchange_crypto") }
    }

    private func open(_ object: [String: Any], text: String, nonce: String, tag: String, secret: Secret) throws -> Data {
        guard let cipher = Data(base64Encoded: Self.string(object[text])),
              let nonceData = Data(base64Encoded: Self.string(object[nonce])), nonceData.count == 12,
              let tagData = Data(base64Encoded: Self.string(object[tag])), tagData.count == 16 else { throw failure("secure_cipher") }
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonceData), ciphertext: cipher, tag: tagData)
        return try AES.GCM.open(box, using: secret.aes, authenticating: aad(secret.id))
    }

    private func now() -> Int64 { clock() + clockOffset }
    private func aad(_ id: String) -> Data { Data((owner + "|" + id).utf8) }
    private func failure(_ phase: String, code: String = "", status: Int = 0) -> OttaiSecureTransportFailure {
        .init(diagnostic: phase + (code.isEmpty ? "" : "_" + code), businessCode: code, httpStatus: status)
    }
    static func successful(_ reply: Reply) -> Bool {
        let code = string(reply.json?["code"])
        return (200...299).contains(reply.status) && reply.json != nil && (code.isEmpty || code == "200" || code.caseInsensitiveCompare("OK") == .orderedSame)
    }
    static func string(_ value: Any?) -> String { (value as? String) ?? (value as? NSNumber)?.stringValue ?? "" }
    static func safeCode(_ value: Any?) -> String {
        let code = string(value)
        return code.range(of: "^[A-Za-z][A-Za-z0-9_]{0,95}$", options: .regularExpression) == nil ? "" : code
    }
    static func jsonString(_ object: Any) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        guard let value = String(data: data, encoding: .utf8) else { throw OttaiSecureTransportFailure(diagnostic: "secure_json") }
        return value
    }
    static func sha256(_ string: String) -> String { SHA256.hash(data: Data(string.utf8)).map { String(format: "%02x", $0) }.joined() }
    static func random(_ count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else { throw OttaiSecureTransportFailure(diagnostic: "secure_random") }
        return Data(bytes)
    }
}
