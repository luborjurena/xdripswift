// SPDX-License-Identifier: GPL-3.0-or-later
// Global-only port of JugglucoNG 11e6e29 OttaiRegionalTransport.kt.
// Existing China and Syai implementations deliberately keep their own transport.
import Foundation

enum OttaiRegionalTransport {
    typealias Send = (String, String, String?, [String: String]) throws -> OttaiNetSecurity.Reply
    struct Route {
        let secureBase: String
        let exchangeURL: String
        let path: String
        let query: [String: String]
    }

    static func route(_ url: String) throws -> Route? {
        guard let parts = URLComponents(string: url) else { throw OttaiSecureTransportFailure(diagnostic: "secure_url") }
        let prefix = "/cgm/app/server"
        guard parts.host?.lowercased() == "seas.ottai.com", parts.path.hasPrefix(prefix + "/") else { return nil }
        guard parts.scheme == "https", parts.port == nil, parts.user == nil, parts.password == nil,
              parts.fragment == nil, !parts.path.contains(".."), !parts.path.contains("?") else {
            throw OttaiSecureTransportFailure(diagnostic: "secure_url")
        }
        var query: [String: String] = [:]
        // Existing caller uses application/x-www-form-urlencoded query encoding.
        for item in (parts.percentEncodedQuery ?? "").split(separator: "&") {
            let pair = item.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            func decode(_ value: Substring) throws -> String {
                guard let decoded = value.replacingOccurrences(of: "+", with: " ").removingPercentEncoding else {
                    throw OttaiSecureTransportFailure(diagnostic: "secure_query")
                }
                return decoded
            }
            query[try decode(pair[0])] = pair.count == 2 ? try decode(pair[1]) : ""
        }
        let secureBase = "https://seas.ottai.com/cgm/security/app/server"
        return Route(secureBase: secureBase, exchangeURL: secureBase + "/security/exchangeKey",
                     path: String(parts.path.dropFirst(prefix.count)), query: query)
    }

    /// Actual production dispatcher; tests inject HTTP here, without an alternate codec.
    static func request(_ method: String, url: String, body: String?, headers: [String: String], send: @escaping Send) throws -> OttaiNetSecurity.Reply {
        guard let route = try route(url) else { return try send(method, url, body, headers) }
        guard let owner = headers["deviceId"], !owner.isEmpty else { throw OttaiSecureTransportFailure(diagnostic: "secure_identity") }
        var common = headers
        // Compatibility threshold from the official secure client: route and version change together.
        common["versionCode"] = "10000000"
        common["webDeviceId"] = owner
        let codec = OttaiNetSecurity(owner: owner, exchange: { object in
            var h = common; h["Content-Type"] = "application/json;charset=UTF-8"
            return try send("POST", route.exchangeURL, OttaiNetSecurity.jsonString(object), h)
        }, send: { verb, path, cipherHeaders, query, payload in
            var h = common.merging(cipherHeaders) { _, new in new }
            if payload != nil { h["Content-Type"] = "application/json;charset=UTF-8" }
            var target = URLComponents(string: route.secureBase + path)!
            if !query.isEmpty {
                let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
                func encode(_ value: String) -> String { value.addingPercentEncoding(withAllowedCharacters: allowed)! }
                target.percentEncodedQuery = query.keys.sorted().map { encode($0) + "=" + encode(query[$0]!) }.joined(separator: "&")
            }
            guard let url = target.url?.absoluteString else { throw OttaiSecureTransportFailure(diagnostic: "secure_url") }
            return try send(verb, url, payload, h)
        })
        defer { codec.close() }
        let reply = try codec.request(method: method, path: route.path, query: route.query, body: body)
        // Legacy callers sometimes parse data even after failure; never return that data from a failed gateway.
        if !OttaiNetSecurity.successful(reply) {
            var safe: [String: Any] = ["code": OttaiNetSecurity.string(reply.json?["code"])]
            if reply.origin == .authenticated {
                let message = ["message", "msg", "detailMessage"].compactMap { reply.json?[$0] as? String }.first { !$0.isEmpty } ?? ""
                let secrets = [headers["Authorization"], headers["deviceId"]].compactMap { $0 } + Array(route.query.values) + sensitiveStrings(body)
                let sanitized = sanitizedMessage(message, redacting: secrets)
                if !sanitized.isEmpty { safe["message"] = sanitized }
            }
            return .init(status: reply.status, json: safe, origin: reply.origin)
        }
        return reply
    }
    /// UI-only error detail from an authenticated response, never a response-body logger.
    static func sanitizedMessage(_ message: String, redacting secrets: [String]) -> String {
        var result = String(message.prefix(2000))
        for value in secrets.filter({ !$0.isEmpty }).sorted(by: { $0.count > $1.count }) {
            result = result.replacingOccurrences(of: value, with: "[redacted]")
        }
        for pattern in [
            #"https?://[^\s<>]+"#,
            #"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"#,
            #"(?i)(?:password|token|secret|signature|authorization|apiToken|keyA|keyB)\s*[:=]\s*[^\s,;]+"#,
            #"[A-Za-z0-9_+/=.-]{24,}"#
        ] {
            result = result.replacingOccurrences(of: pattern, with: "[redacted]", options: .regularExpression)
        }
        result = result.components(separatedBy: .whitespacesAndNewlines).filter { !$0.isEmpty }.joined(separator: " ")
        return String(result.prefix(240))
    }
    private static func sensitiveStrings(_ body: String?) -> [String] {
        guard let body, let json = try? JSONSerialization.jsonObject(with: Data(body.utf8)) else { return [] }
        func strings(_ value: Any) -> [String] {
            if let string = value as? String { return [string] }
            if let dictionary = value as? [String: Any] { return dictionary.values.flatMap(strings) }
            if let array = value as? [Any] { return array.flatMap(strings) }
            return []
        }
        return strings(json)
    }

}
