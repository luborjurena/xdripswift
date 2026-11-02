// SPDX-License-Identifier: GPL-3.0-or-later
// Global Android 1.38.0 / 261721 passwordLogin contract, libapp.so SHA256
// a62a948d17f4d45ff69e333181f2ee62877ba3131c5f29c921fae885d96ee743.
// Verified with native login + own sensor reads + material decryption on 2026-11-02.
import Foundation

enum OttaiGlobalContract {
    typealias Failure = OttaiCloudClient.CloudFailure
    typealias Login = OttaiCloudClient.LoginResult
    static let appName = "ottai-seas"
    static let packageName = "com.ottai.seas"
    static let loginURL = OttaiConstants.apiBaseGlobal + OttaiConstants.prefix + "/user/login/variousLogin"
    static let deviceIDPrefix = "ottai-seas:a:g:"

    struct Request {
        let method: String
        let url: String
        var query: [String: String] = [:]
        var body: [String: Any]?
        let headers: [String: String]
    }
    typealias Send = (Request) -> OttaiCloudClient.RequestResult

    static func validDeviceID(_ value: String) -> Bool {
        guard value.hasPrefix(deviceIDPrefix) else { return false }
        let suffix = value.dropFirst(deviceIDPrefix.count)
        return suffix.count == 32 && suffix.utf8.allSatisfy { (65...90).contains($0) || (48...57).contains($0) }
    }

    static func makeDeviceID() -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        return deviceIDPrefix + String((0..<32).map { _ in alphabet.randomElement()! })
    }

    static func headers(deviceID: String, timestamp: Int64, accessToken: String, deviceModel: String) -> [String: String] {
        var result: [String: String] = [
            "appName": appName, "packageName": packageName, "deviceId": deviceID,
            "versionName": "1.38.0", "versionCode": "261721", "ua": "Android",
            "timestamp": String(timestamp), "traceId": UUID().uuidString.lowercased(),
            "country": "GB", "region": "GB", "language": "en", "unit": "mmol_L",
            "applicationType": "ottai_seas", "deviceModel": deviceModel,
            "timezone": String(TimeZone.current.secondsFromGMT()),
            "timeZoneName": TimeZone.current.abbreviation() ?? "UTC"
        ]
        if !accessToken.isEmpty { result["Authorization"] = accessToken }
        return result
    }

    /// CgmServiceManger.getMacAuthGroup in the Global M8 SDK (Android 1.38.0).
    /// This endpoint only reads keys; it must not bind, release or activate a sensor.
    static func authInfoRequest(mac: String, deviceID: String, accessToken: String,
                                timestamp: Int64, deviceModel: String) -> Request? {
        let canonical = OttaiConstants.canonicalSensorId(mac)
        guard OttaiConstants.looksLikeMac(canonical), validDeviceID(deviceID), !accessToken.isEmpty else { return nil }
        var h = headers(deviceID: deviceID, timestamp: timestamp, accessToken: accessToken, deviceModel: deviceModel)
        h["productModel"] = "M8"
        return Request(method: "GET", url: OttaiConstants.apiBaseGlobal + OttaiConstants.prefix + "/device/authInfo",
            query: ["mac": canonical, "sign": OttaiCloudClient.globalAuthInfoSign(deviceID: deviceID, timestampMillis: timestamp, mac: canonical)], headers: h)
    }

    /// authInfo contains keys and lifetime metadata but no formula/coefficients.
    /// Preserve the validated calculation data and reject any cross-sensor merge.
    static func mergeAuthInfo(validation: [String: Any], authInfo: [String: Any], mac: String) -> [String: Any]? {
        guard let validationData = validation["data"] as? [String: Any],
              let authData = authInfo["data"] as? [String: Any] else { return nil }
        var vo = validationData["cgmDeviceRespVO"] as? [String: Any] ?? validationData
        let canonical = OttaiConstants.canonicalSensorId(mac)
        guard OttaiConstants.canonicalSensorId(vo["mac"] as? String) == canonical,
              OttaiConstants.canonicalSensorId(authData["mac"] as? String) == canonical else { return nil }
        for key in ["keyA", "produceTime", "retainTime"] {
            if let value = authData[key], !(value is NSNull), (value as? String)?.isEmpty != true { vo[key] = value }
        }
        for (key, fallback) in ["activeExpireTime": OttaiGlobalActivation.defaultActiveExpireMs,
                                "preheatPeriodTime": Int64(0), "gracePeriodTime": Int64(0)] {
            if let value = authData[key], !(value is NSNull) { vo[key] = value }
            else { vo[key] = fallback }
        }
        guard let key = vo["keyA"] as? String, !key.isEmpty else { return nil }
        var result = validationData
        result["cgmDeviceRespVO"] = vo
        return ["data": result]
    }

    /// The production preparation flow for an unused Global M8. Its injected port
    /// is read-only by construction; preparation can never bind/unbind or start it.
    static func checkedSensor(mac: String, deviceID: String, accessToken: String, deviceModel: String,
                              send: Send, clock: () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }) -> Result<[String: Any], Failure> {
        let canonical = OttaiConstants.canonicalSensorId(mac)
        guard OttaiConstants.looksLikeMac(canonical), validDeviceID(deviceID), !accessToken.isEmpty else {
            return .failure(Failure(text: "A sensor ID and signed-in Global session are required.", stage: "Check sensor"))
        }
        let ts = clock()
        var validationHeaders = headers(deviceID: deviceID, timestamp: ts, accessToken: accessToken, deviceModel: deviceModel)
        validationHeaders["productModel"] = "M8"
        let validationRequest = Request(method: "GET", url: OttaiConstants.apiBaseGlobal + OttaiConstants.epValidateByMac,
            query: ["mac": canonical, "signature": OttaiCloudClient.signForProfile(.globalPhone, deviceId: deviceID, ts: ts, canonical)],
            headers: validationHeaders)
        let validation = send(validationRequest)
        if let failure = validation.failure { return .failure(failure) }
        guard let body = validation.body,
              let request = authInfoRequest(mac: canonical, deviceID: deviceID, accessToken: accessToken,
                                            timestamp: clock(), deviceModel: deviceModel) else {
            return .failure(Failure(text: "The Global sensor check returned no usable metadata.", stage: "Check sensor"))
        }
        let authInfo = send(request)
        if let failure = authInfo.failure { return .failure(failure) }
        guard let authBody = authInfo.body, let merged = mergeAuthInfo(validation: body, authInfo: authBody, mac: canonical) else {
            return .failure(Failure(text: "The Global server did not return matching sensor keys. No activation was attempted.", stage: "Sensor credentials"))
        }
        return .success(merged)
    }

    static func passwordBody(email: String, password: String, apiToken: String, signature: String) -> [String: Any]? {
        // Preserve the official compact JSON field order, including proper escaping.
        func quoted(_ value: String) -> String? {
            guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed, .withoutEscapingSlashes]) else { return nil }
            return String(data: data, encoding: .utf8)
        }
        guard let username = quoted(email), let secret = quoted(password) else { return nil }
        let plain = "{\"username\":\(username),\"password\":\(secret)}"
        let key = Array("miH5ngQ7z4NZU3JgZFq87Gg6v1Y7YJm9".utf8)
        guard let ciphertext = OttaiCrypto.aesECB(.encrypt, key: key, data: Array(plain.utf8), pkcs7Padded: true) else { return nil }
        return ["encryptInfo": Data(ciphertext).base64EncodedString(), "apiToken": apiToken, "signature": signature, "type": "2", "phoneCode": ""]
    }

    /// Native candidate remains local until both own-account read APIs validate it.
    /// No registry mutation, password retry, web fallback or sensor mutation exists here.
    static func authenticate(email: String, password: String, deviceID: String, deviceModel: String,
                             send: Send, clock: () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }) -> Result<Login, Failure> {
        let account = email.trimmingCharacters(in: .whitespacesAndNewlines)
        var privateValues = [account, password]
        func failed(_ failure: Failure, stage: String) -> Failure { privateFailure(failure, stage: stage, redacting: privateValues) }
        guard !account.isEmpty, !password.isEmpty, validDeviceID(deviceID) else {
            return .failure(Failure(text: "Email, password and a valid installation identity are required.", stage: "Global sign-in"))
        }
        func header(_ timestamp: Int64, token: String = "") -> [String: String] {
            headers(deviceID: deviceID, timestamp: timestamp, accessToken: token, deviceModel: deviceModel)
        }
        let tokenTime = clock()
        let tokenReply = send(Request(method: "GET", url: OttaiConstants.apiBaseGlobal + OttaiConstants.epApiToken,
            query: ["signature": OttaiCloudClient.signForProfile(.globalPhone, deviceId: deviceID, ts: tokenTime)], headers: header(tokenTime)))
        if let failure = tokenReply.failure { return .failure(failed(failure, stage: "Global API token")) }
        guard let apiToken = tokenReply.body?["data"] as? String, !apiToken.isEmpty else {
            return .failure(Failure(text: "The server returned no API token.", stage: "Global API token"))
        }
        privateValues.append(apiToken)
        let loginTime = clock()
        let signature = OttaiCloudClient.signForProfile(.globalPhone, deviceId: deviceID, ts: loginTime, apiToken, account, password)
        guard let body = passwordBody(email: account, password: password, apiToken: apiToken, signature: signature) else {
            return .failure(Failure(text: "Could not prepare the encrypted sign-in request.", stage: "Global sign-in"))
        }
        let loginReply = send(Request(method: "POST", url: loginURL, body: body, headers: header(loginTime)))
        if let failure = loginReply.failure { return .failure(failed(failure, stage: "Global sign-in")) }
        guard let data = loginReply.body?["data"] as? [String: Any] ?? loginReply.body?["result"] as? [String: Any] else {
            return .failure(Failure(text: "The server returned no account data.", stage: "Global sign-in"))
        }
        let candidate = OttaiLoginFlow.mobileLogin(data)
        guard candidate.ok, !candidate.userId.isEmpty else {
            return .failure(Failure(text: "The server returned incomplete account credentials.", stage: "Global sign-in"))
        }
        privateValues += [candidate.accessToken, candidate.glucoseSecretKey, candidate.userId]
        let current = send(Request(method: "GET", url: OttaiConstants.apiBaseGlobal + OttaiConstants.epGetBindDevice, headers: header(clock(), token: candidate.accessToken)))
        if let failure = current.failure { return .failure(failed(failure, stage: "Global account validation")) }
        do { _ = try OttaiAccountSensors.snapshot(current: .init(body: current.body, failure: nil), history: nil) }
        catch { return .failure(Failure(text: "The account binding response has an unsupported format.", stage: "Global account validation")) }
        let history = send(Request(method: "GET", url: OttaiConstants.apiBaseGlobal + OttaiConstants.epDeviceList,
            query: ["pageSize": "80", "pageNumber": "1"], headers: header(clock(), token: candidate.accessToken)))
        if let failure = history.failure { return .failure(failed(failure, stage: "Global account validation")) }
        do {
            _ = try OttaiAccountSensors.snapshot(current: .init(body: current.body, failure: nil), history: .init(body: history.body, failure: nil))
            let historyData = history.body?["data"] as? [String: Any] ?? history.body?["result"] as? [String: Any] ?? [:]
            let rows = (historyData["items"] ?? historyData["list"] ?? historyData["records"]) as? [[String: Any]] ?? []
            if !rows.isEmpty && !rows.contains(where: { row in
                let device = row["cgmDeviceRespVO"] as? [String: Any] ?? row
                return OttaiAccountSensors.canonicalMAC(device["mac"] as? String ?? row["mac"] as? String ?? "") != nil
            }) {
                return .failure(Failure(text: "The sensor history contains no supported records.", stage: "Global account validation"))
            }
        } catch {
            return .failure(Failure(text: "The account sensor response has an unsupported format.", stage: "Global account validation"))
        }
        return .success(candidate)
    }

    /// Auth errors may echo encrypted request contents; never expose free-form server text.
    private static func privateFailure(_ failure: Failure, stage: String, redacting privateValues: [String]) -> Failure {
        var code = OttaiNetSecurity.safeCode(failure.code)
        if privateValues.contains(where: { !$0.isEmpty && code.contains($0) }) { code = "server_error" }
        return Failure(text: "Request failed (HTTP \(failure.httpStatus), code \(code)).", code: code,
                       httpStatus: failure.httpStatus, stage: stage, origin: failure.origin)
    }
}
