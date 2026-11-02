//
//  OttaiCloudClient.swift
//  xdrip
//
//  Ottai / Syai CGM driver — talks to the cloud (login, check and bind a sensor,
//  cgmAuth, unbind, decrypt the sensor keys). Works with all three servers:
//  China (api.ottai.com, phone + SMS), Global (seas.ottai.com), Syai
//  (api.syai.com), and also the website API for email login and sign-up.
//
//  This is a Swift copy of OttaiCloudClient.kt from JugglucoNG. The HTTP calls
//  wait for the answer, so call them from a background queue, never from the
//  main thread.
//

import CryptoKit
import Foundation

enum OttaiCloudClient {

    // The secret used to sign requests. The old endpoints and cgmAuth use MD5.
    private static let seed = "dy7234hbnrnfh7q89eru8ybfn899"
    private static let watchAppName = "ottai-watch"
    private static let watchPkg = "com.ottai.tag.watch"
    private static let phoneAppName = "ottai"
    private static let phonePkg = "com.ottai.tag"
    private static let timeoutMs = 30_000
    private static let temporaryUnbindDelayMs: UInt32 = 2_000

    // Error codes from the server that the caller must handle.
    static let bizAlreadyBinding = "AppUser_AlreadyBinding"
    static let bizOutOfProduceTime = "AppDevice_OutOfProduceTime"
    static let bizUpgradeVersion = "AppDevice_Upgrade_Version"
    static let bizEndUsing = "AppDevice_EndUsing"

    struct CloudFailure: Error {
        let text: String
        var code: String = ""
        var httpStatus: Int = 0
        var stage: String = ""
        var origin: String = ""
        var displayText: String { stage.isEmpty ? text : stage + (origin.isEmpty ? "" : " [" + origin + "]") + ": " + text }
        func contextualized(stage: String, origin: String = "") -> CloudFailure {
            var copy = self; copy.stage = stage; copy.origin = origin; return copy
        }
        var isTokenInvalid: Bool { code.caseInsensitiveCompare("AuthFailed_TokenInvalid") == .orderedSame }
        var requiresSignIn: Bool { httpStatus == 401 || code == "401" || isTokenInvalid || code == "AuthFailed_LoginElsewhere" }
    }

    /// Why the last call failed (no secrets in it). Nil after a call that worked.
    static var lastFailure: CloudFailure?
    static var lastError: String { lastFailure?.displayText ?? "" }

    struct LoginResult {
        let userId: String
        let accessToken: String
        let glucoseSecretKey: String
        var ok: Bool { !accessToken.isEmpty && !glucoseSecretKey.isEmpty }
    }

    struct DeviceResp {
        var mac: String
        var keyA: String
        var method: String
        var coefficient: String
        var produceTime: Int64
        var methodUpdateTime: Int64
        var coeffUpdateTime: Int64
        var activeTime: Int64
        var activeExpireTime: Int64  // sensor lifetime in ms
        var preheatPeriodTime: Int64
        var retainTime: Int64        // "destruction" time in ms
        var deviceVersion: String
        var deviceId: Int
        var gracePeriodTime: Int64 = 0
        var calibrationValueK: Double?
        var calibrationValueB: Double?
    }

    struct DeviceValidation {
        let device: DeviceResp
        /// New China sensors answer the V3 check with info only. keyA comes later from bindV3.
        let requiresV3Bind: Bool
    }

    struct DeviceSummary {
        let mac: String
        let serialNo: String
        let deviceType: String
        let deviceVersion: String
        let bindTime: Int64
        let unbindTime: Int64
        var isActive: Bool { unbindTime <= 0 }
    }

    /// cgmAuth/verify answer (hex). cf, d, c = coefficient, duration and activate frames,
    /// encrypted by the server for this one connection.
    struct V3AuthMaterial {
        let authHost: String
        let authFlag: String
        let keyB: String
        let cf: String
        let d: String
        let c: String
        var ok: Bool { !authHost.isEmpty && !authFlag.isEmpty }
        var hasActivationFrames: Bool { !cf.isEmpty && !d.isEmpty && !c.isEmpty }
    }

    enum MaterialsOutcome {
        case saved
        /// New sensor: keyA comes only from the bind after the server-assisted activation.
        case readyForServerActivation
        case failed
    }

    // MARK: - identity / signature

    private struct ApiIdentity {
        let appName: String
        let packageName: String
        var fullDeviceID = false
        func deviceId(_ value: String) -> String { fullDeviceID ? value : "\(appName):a:\(value)" }
    }

    private static func sessionIdentity(_ profile: OttaiRegistry.SessionProfile) -> ApiIdentity {
        switch profile {
        case .cnPhone: return ApiIdentity(appName: phoneAppName, packageName: phonePkg)
        case .globalPhone: return ApiIdentity(appName: OttaiGlobalContract.appName, packageName: OttaiGlobalContract.packageName, fullDeviceID: true)
        case .watch: return ApiIdentity(appName: watchAppName, packageName: watchPkg)
        }
    }

    private static func md5Hex(_ s: String) -> String {
        // The cloud signs with MD5. CryptoKit returns a digest sequence; keep the previous
        // lowercase hex string format.
        Insecure.MD5.hash(data: Data(s.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    static func signForProfile(_ profile: OttaiRegistry.SessionProfile, deviceId: String, ts: Int64, _ args: String...) -> String {
        let identity = sessionIdentity(profile)
        return md5Hex(identity.appName + identity.deviceId(deviceId) + String(ts) + args.joined() + seed)
    }

    static func cgmAuthVerifySign(_ profile: OttaiRegistry.SessionProfile, deviceId: String, timestampMillis: Int64, mac: String, paramStr: String, shaInfo: String) -> String {
        let identity = sessionIdentity(profile)
        return md5Hex(identity.appName + identity.deviceId(deviceId) + mac.uppercased() + paramStr.uppercased() + shaInfo.uppercased() + String(timestampMillis) + seed)
    }

    static func globalAuthInfoSign(deviceID: String, timestampMillis: Int64, mac: String) -> String {
        md5Hex(seed + OttaiGlobalContract.appName + deviceID + mac.uppercased() + String(timestampMillis) + seed)
    }

    static func activeProfile(_ apiBase: String, stored: OttaiRegistry.SessionProfile = OttaiRegistry.loadSessionProfile()) -> OttaiRegistry.SessionProfile {
        if apiBase == OttaiConstants.apiBaseGlobal { return stored == .globalPhone ? .globalPhone : .watch }
        if apiBase == OttaiConstants.apiBase { return stored == .cnPhone ? .cnPhone : .watch }
        return .watch
    }

    private static func requestDeviceId(_ profile: OttaiRegistry.SessionProfile) -> String {
        switch profile {
        case .cnPhone: return OttaiRegistry.loadCnHeaderDeviceId()
        case .globalPhone: return OttaiRegistry.loadOrCreateGlobalHeaderDeviceId()
        case .watch: return OttaiRegistry.loadOrCreateDeviceId()
        }
    }

    private static func headers(ts: Int64, apiBase: String, authorizationOverride: String? = nil, profileOverride: OttaiRegistry.SessionProfile? = nil) -> [String: String] {
        let token = authorizationOverride ?? OttaiRegistry.loadAccessToken()
        let profile = profileOverride ?? activeProfile(apiBase)
        let deviceId = requestDeviceId(profile)
        if profile == .globalPhone {
            return OttaiGlobalContract.headers(deviceID: deviceId, timestamp: ts, accessToken: token, deviceModel: OttaiCloudUploader.deviceModel)
        }
        if profile == .cnPhone {
            var h = cnPhoneHeaders(deviceId: deviceId, accessToken: token, timestamp: ts, traceId: UUID().uuidString)
            if token.isEmpty { h.removeValue(forKey: "Authorization") }
            return h
        }
        let identity = sessionIdentity(.watch)
        let offsetSec = TimeZone.current.secondsFromGMT()
        var h: [String: String] = [
            "appName": identity.appName,
            "versionName": "1.1.0",
            "versionCode": "244301",
            "packageName": identity.packageName,
            "ua": "Android_Watch_Ottai_Arc",
            "timezone": String(offsetSec),
            "timeZoneName": TimeZone.current.identifier,
            "language": Locale.current.language.languageCode?.identifier ?? "en",
            "traceId": "trace_testtest",
            "timestamp": String(ts),
            "country": "zh_CN",
            "deviceId": identity.deviceId(deviceId),
        ]
        // The China server only accepts China IPs. Send a fake one, but ONLY to that server.
        if apiBase == OttaiConstants.apiBase {
            h["X-Forwarded-For"] = OttaiConstants.cnForwardIp
            h["X-Real-IP"] = OttaiConstants.cnForwardIp
            h["CF-Connecting-IP"] = OttaiConstants.cnForwardIp
            h["True-Client-IP"] = OttaiConstants.cnForwardIp
        }
        if !token.isEmpty { h["Authorization"] = token }
        return h
    }

    private static func cnPhoneHeaders(deviceId: String, accessToken: String, timestamp: Int64, traceId: String) -> [String: String] {
        let identity = sessionIdentity(.cnPhone)
        return [
            "User-Agent": "Dart/3.8 (dart:io)",
            "ua": "Android",
            "deviceId": identity.deviceId(deviceId),
            "applicationType": "ottai_main",
            "appName": identity.appName,
            "versionCode": "263121",
            "country": "CN",
            "language": "zh",
            "timezone": "28800",
            "packageName": identity.packageName,
            "productModel": "MB",
            "unit": "mmol_L",
            "timeZoneName": "Asia/Shanghai",
            "deviceModel": "SM-A205FN",
            "versionName": "1.55.0",
            "X-Forwarded-For": OttaiConstants.cnForwardIp,
            "X-Real-IP": OttaiConstants.cnForwardIp,
            "CF-Connecting-IP": OttaiConstants.cnForwardIp,
            "True-Client-IP": OttaiConstants.cnForwardIp,
            "timestamp": String(timestamp),
            "traceId": traceId,
            "Authorization": accessToken,
        ]
    }

    private static func now() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }
    private static func base() -> String { OttaiRegistry.loadApiBase() }
    /// The Syai server goes through OttaiSyaiClient (encrypted, as the Syai Tag app).
    private static var isSyai: Bool { base() == OttaiConstants.apiBaseSyai }

    /// Syai needs a Syai Tag session (with a refresh token); an older login does not count.
    static var isSignedIn: Bool {
        !OttaiRegistry.loadAccessToken().isEmpty && !OttaiRegistry.loadGlucoseSecretKey().isEmpty
            && (!isSyai || !OttaiRegistry.loadRefreshToken().isEmpty)
    }

    private static func normalizePhone(_ raw: String) -> String {
        var d = raw.filter { $0.isNumber }
        if d.count == 13 && d.hasPrefix("86") { d = String(d.dropFirst(2)) }
        if d.count == 14 && d.hasPrefix("0086") { d = String(d.dropFirst(4)) }
        return d
    }

    // MARK: - login

    static func getApiToken(apiBase: String = base(), authorizationOverride: String? = nil, profileOverride: OttaiRegistry.SessionProfile? = nil) -> String? {
        let ts = now()
        let profile = profileOverride ?? activeProfile(apiBase)
        let deviceId = requestDeviceId(profile)
        let sig = signForProfile(profile, deviceId: deviceId, ts: ts)
        let resp = httpGet(apiBase + OttaiConstants.epApiToken, ["signature": sig], headers(ts: ts, apiBase: apiBase, authorizationOverride: authorizationOverride, profileOverride: profile))
        return str(resp, "data").nilIfEmpty
    }

    static func requestSmsCode(phone: String, phoneCode: String = "86") -> String? {
        let profile = OttaiRegistry.SessionProfile.cnPhone
        guard let apiToken = getApiToken(apiBase: OttaiConstants.apiBase, authorizationOverride: "", profileOverride: profile) else {
            lastFailure = CloudFailure(text: "apiToken failed"); return nil
        }
        let ts = now()
        let deviceId = requestDeviceId(profile)
        let ph = normalizePhone(phone)
        let body: [String: Any] = [
            "phoneCode": phoneCode, "phone": ph, "apiToken": apiToken, "smsType": 1,
            "signature": signForProfile(profile, deviceId: deviceId, ts: ts, ph, apiToken),
        ]
        let resp = httpPostJson(OttaiConstants.apiBase + OttaiConstants.epSmsCode, json(body), headers(ts: ts, apiBase: OttaiConstants.apiBase, authorizationOverride: "", profileOverride: profile))
        return str(resp, "data").nilIfEmpty
    }

    static func smsLogin(phone: String, code: String, requestId: String, phoneCode: String = "86") -> LoginResult? {
        let profile = OttaiRegistry.SessionProfile.cnPhone
        let ts = now()
        let deviceId = requestDeviceId(profile)
        let ph = normalizePhone(phone)
        let body: [String: Any] = [
            "phoneCode": phoneCode, "phone": ph, "validCode": code, "requestId": requestId,
            "signature": signForProfile(profile, deviceId: deviceId, ts: ts, requestId, ph, code),
        ]
        guard let resp = httpPostJson(OttaiConstants.apiBase + OttaiConstants.epSmsLogin, json(body), headers(ts: ts, apiBase: OttaiConstants.apiBase, authorizationOverride: "", profileOverride: profile)),
              let data = dataObject(resp) else { return nil }
        let result = LoginResult(userId: str(data, "userId"), accessToken: str(data, "accessToken"), glucoseSecretKey: str(data, "glucoseSecretKey"))
        if result.ok {
            OttaiRegistry.saveApiBase(OttaiConstants.apiBase)
            OttaiRegistry.saveSessionProfile(profile)
            OttaiRegistry.saveAccessToken(result.accessToken)
            OttaiRegistry.saveGlucoseSecretKey(result.glucoseSecretKey)
            OttaiRegistry.saveUserId(result.userId)
        }
        return result
    }

    /// A login never inherits an earlier stored token. Only an explicit web-token override is allowed.
    static func passwordLogin(account: String, password: String, base baseUrl: String = OttaiConstants.apiBaseGlobal, authorizationOverride: String? = nil) -> LoginResult? {
        finishMobileLogin(nativePasswordLogin(account: account, password: password, base: baseUrl, authorization: authorizationOverride ?? ""), apiBase: baseUrl)
    }

    private static func nativePasswordLogin(account: String, password: String, base baseUrl: String, authorization: String) -> Result<LoginResult, CloudFailure> {
        let acct = account.trimmingCharacters(in: .whitespaces)
        guard !acct.isEmpty, !password.isEmpty else { return .failure(CloudFailure(text: "Account/password required.")) }
        let profile = OttaiRegistry.SessionProfile.watch
        let deviceId = requestDeviceId(profile)
        let tokenTs = now()
        let tokenReply = httpGetResult(baseUrl + OttaiConstants.epApiToken,
            ["signature": signForProfile(profile, deviceId: deviceId, ts: tokenTs)],
            headers(ts: tokenTs, apiBase: baseUrl, authorizationOverride: authorization, profileOverride: profile))
        if let failure = tokenReply.failure { return .failure(failure) }
        guard let apiToken = str(tokenReply.body, "data").nilIfEmpty else { return .failure(CloudFailure(text: "Mobile apiToken failed.")) }
        let ts = now()
        let body: [String: Any] = ["account": acct, "username": acct, "userName": acct, "password": password, "apiToken": apiToken,
            "signature": signForProfile(profile, deviceId: deviceId, ts: ts, apiToken, acct, password)]
        let reply = httpPostJsonResult(baseUrl + OttaiConstants.epAccountLogin, json(body),
            headers(ts: ts, apiBase: baseUrl, authorizationOverride: authorization, profileOverride: profile))
        if let failure = reply.failure { return .failure(failure) }
        guard let data = dataObject(reply.body) else { return .failure(CloudFailure(text: "Mobile login returned no account data.")) }
        let result = OttaiLoginFlow.mobileLogin(data)
        return result.ok ? .success(result) : .failure(CloudFailure(text: "Mobile login returned incomplete credentials."))
    }

    private static func finishMobileLogin(_ reply: Result<LoginResult, CloudFailure>, apiBase: String) -> LoginResult? {
        switch reply {
        case .failure(let failure): lastFailure = failure; return nil
        case .success(let result):
            guard result.ok else { lastFailure = CloudFailure(text: "Mobile login returned incomplete credentials."); return nil }
            OttaiRegistry.saveApiBase(apiBase)
            OttaiRegistry.saveSessionProfile(.watch)
            OttaiRegistry.saveAccessToken(result.accessToken)
            OttaiRegistry.saveGlucoseSecretKey(result.glucoseSecretKey)
            OttaiRegistry.saveUserId(result.userId)
            lastFailure = nil
            return result
        }
    }

    static func logout() {
        if isSyai {
            OttaiSyaiClient.logout()
        } else {
            _ = httpPostJson(base() + OttaiConstants.epLogout, "{}", headers(ts: now(), apiBase: base()))
        }
        OttaiRegistry.clearAccountSession()
        OttaiRegistry.saveAccountLogin(nil)
        OttaiRegistry.saveCloudUploadStatus(nil)
    }

    // MARK: - device validate / bind

    static func validateByMac(mac: String) -> DeviceResp? {
        guard let v = validateForSetup(mac: mac), !v.device.keyA.isEmpty else { return nil }
        return v.device
    }

    static func validateForSetup(mac: String) -> DeviceValidation? {
        let canonical = OttaiConstants.canonicalSensorId(mac)
        if canonical.isEmpty { return nil }
        let apiBase = base()
        // Syai checks every sensor with V3, as the Syai Tag app does.
        if isSyai {
            guard let resp = OttaiSyaiClient.validateDeviceByMacV3(mac: canonical),
                  let device = parseDeviceResp(resp, requireKeyA: false) else { return nil }
            OttaiRegistry.saveLastValidatedDeviceVersion(sensorId: canonical, version: device.deviceVersion)
            return DeviceValidation(device: device, requiresV3Bind: device.keyA.isEmpty)
        }
        let ts = now()
        let profile = activeProfile(apiBase)
        let deviceId = requestDeviceId(profile)
        if profile == .globalPhone {
            let result = OttaiGlobalContract.checkedSensor(mac: canonical, deviceID: deviceId,
                accessToken: OttaiRegistry.loadAccessToken(), deviceModel: OttaiCloudUploader.deviceModel,
                send: { request in httpGetResult(request.url, request.query, request.headers) })
            switch result {
            case .failure(let failure): lastFailure = failure; return nil
            case .success(let response):
                guard let device = parseDeviceResp(response) else {
                    lastFailure = CloudFailure(text: "The Global server returned incomplete sensor credentials.")
                    return nil
                }
                OttaiRegistry.saveLastValidatedDeviceVersion(sensorId: canonical, version: device.deviceVersion)
                return DeviceValidation(device: device, requiresV3Bind: false)
            }
        }
        let resp = httpGet(apiBase + OttaiConstants.epValidateByMac,
                           ["mac": canonical, "signature": signForProfile(profile, deviceId: deviceId, ts: ts, canonical)],
                           headers(ts: ts, apiBase: apiBase, profileOverride: profile))
        if let resp = resp, let device = parseDeviceResp(resp) {
            return DeviceValidation(device: device, requiresV3Bind: false)
        }
        let v2Failure = lastFailure
        guard shouldTryValidateV3(apiBase: apiBase, profile: profile, v2FailureCode: v2Failure?.code ?? "") else { return nil }
        let v3Ts = now()
        let body: [String: Any] = ["mac": canonical, "signature": signForProfile(profile, deviceId: deviceId, ts: v3Ts, canonical)]
        guard let v3 = httpPostJson(apiBase + OttaiConstants.epValidateByMacV3, json(body), headers(ts: v3Ts, apiBase: apiBase, profileOverride: profile)),
              let device = parseDeviceResp(v3, requireKeyA: false) else {
            if (lastFailure?.code ?? "").isEmpty, v2Failure != nil { lastFailure = v2Failure }
            return nil
        }
        OttaiRegistry.saveLastValidatedDeviceVersion(sensorId: canonical, version: device.deviceVersion)
        return DeviceValidation(device: device, requiresV3Bind: device.keyA.isEmpty)
    }

    /// China only, when V2 asks for a newer app. (Syai always uses V3, see validateForSetup.)
    static func shouldTryValidateV3(apiBase: String, profile: OttaiRegistry.SessionProfile, v2FailureCode: String) -> Bool {
        apiBase == OttaiConstants.apiBase && profile == .cnPhone && v2FailureCode.caseInsensitiveEquals(bizUpgradeVersion)
    }

    /// legacy: activeTime in ms. v3 (China): seconds, newBindType 2. Syai binds through OttaiSyaiClient.bindV3.
    enum BindContract { case legacy, v3, globalM8 }

    static func bindRequestBody(mac: String, deviceVersion: String, userId: String?, activeTime: Int64, contract: BindContract) -> [String: Any] {
        var body: [String: Any] = ["mac": mac, "deviceType": "cgm", "deviceVersion": deviceVersion, "activeTime": activeTime]
        if let userId = userId, !userId.isEmpty { body["userId"] = userId }
        if contract == .v3 { body["newBindType"] = 2 }
        if contract == .globalM8 { body["newBindType"] = 1 }
        return body
    }

    static func bind(mac: String, deviceVersion: String, userId: String) -> DeviceResp? {
        bind(mac: mac, deviceVersion: deviceVersion, userId: userId,
             contract: activeProfile(base()) == .globalPhone ? .globalM8 : .legacy)
    }

    private static func bind(mac: String, deviceVersion: String, userId: String?, contract: BindContract, activeTimeMs: Int64? = nil) -> DeviceResp? {
        let canonical = OttaiConstants.canonicalSensorId(mac)
        if canonical.isEmpty || deviceVersion.isEmpty { lastFailure = CloudFailure(text: "bind requires mac and deviceVersion"); return nil }
        if isSyai {
            let resp = OttaiSyaiClient.bindV3(mac: canonical, deviceVersion: deviceVersion.trimmingCharacters(in: .whitespaces), activeTimeMs: activeTimeMs ?? now())
            return resp.flatMap { parseDeviceResp($0) }
        }
        if contract == .v3 && (userId?.isEmpty ?? true) { lastFailure = CloudFailure(text: "bindV3 requires a signed-in session (userId)"); return nil }
        let ts = now()
        let activeMs = activeTimeMs ?? ts
        let body = bindRequestBody(mac: canonical, deviceVersion: deviceVersion.trimmingCharacters(in: .whitespaces), userId: userId,
                                   activeTime: contract == .v3 ? activeMs / 1000 : activeMs, contract: contract)
        let endpoint = contract == .v3 ? OttaiConstants.epBindV3 : OttaiConstants.epBind
        guard let resp = httpPostJson(base() + endpoint, json(body), headers(ts: ts, apiBase: base())) else { return nil }
        return parseDeviceResp(resp)
    }

    static let syaiMaterialBindDeviceVersion = "E1.1.4(V1.7.S2530.1)"
    static let globalMaterialBindDeviceVersion = "vE1.2.3(V1.7.SH2542.1)"

    static func materialBindDeviceVersion(apiBase: String, selectedDeviceVersion: String?, failureCode: String?) -> String? {
        if let sel = selectedDeviceVersion?.trimmingCharacters(in: .whitespaces), !sel.isEmpty { return sel }
        if !(failureCode?.caseInsensitiveEquals(bizOutOfProduceTime) ?? false) { return nil }
        switch apiBase {
        case OttaiConstants.apiBaseSyai: return syaiMaterialBindDeviceVersion
        case OttaiConstants.apiBaseGlobal: return globalMaterialBindDeviceVersion
        default: return nil
        }
    }

    static func materialBindDeviceVersion(selectedDeviceVersion: String?, failureCode: String?) -> String? {
        materialBindDeviceVersion(apiBase: base(), selectedDeviceVersion: selectedDeviceVersion, failureCode: failureCode)
    }

    static func bindForMaterials(mac: String, deviceVersion: String, historicalActiveTimeMs: Int64 = 0) -> DeviceResp? {
        let canonical = OttaiConstants.canonicalSensorId(mac)
        let userId = OttaiRegistry.loadUserId()
        guard let resp = bind(mac: canonical, deviceVersion: deviceVersion.trimmingCharacters(in: .whitespaces), userId: userId, contract: .legacy) else { return nil }
        let bindFailure = lastFailure
        usleep(temporaryUnbindDelayMs * 1000)
        _ = unbind(mac: canonical, headerOverride: nil)
        lastFailure = bindFailure
        return sanitizeTemporaryBindResponse(resp, historicalActiveTimeMs: historicalActiveTimeMs)
    }

    static func sanitizeTemporaryBindResponse(_ response: DeviceResp, historicalActiveTimeMs: Int64) -> DeviceResp {
        var r = response
        r.activeTime = historicalActiveTimeMs > 0 ? historicalActiveTimeMs : 0
        return r
    }

    // MARK: - cgmAuth (V3 Active_Auth)

    static func cgmAuthVerify(mac: String, authDevHex: String, authFlagHex: String) -> V3AuthMaterial? {
        let canonical = OttaiConstants.canonicalSensorId(mac)
        if canonical.isEmpty { lastFailure = CloudFailure(text: "verify requires mac"); return nil }
        let paramStr = authDevHex.uppercased()
        let shaInfo = authFlagHex.uppercased()
        let answer: [String: Any]?
        if isSyai {
            answer = OttaiSyaiClient.cgmAuthVerify(mac: canonical, paramStr: paramStr, shaInfo: shaInfo)
        } else {
            let apiBase = base()
            let profile = activeProfile(apiBase)
            let ts = now()
            let sign = cgmAuthVerifySign(profile, deviceId: requestDeviceId(profile), timestampMillis: ts, mac: canonical, paramStr: paramStr, shaInfo: shaInfo)
            let body: [String: Any] = ["mac": canonical, "paramStr": paramStr, "shaInfo": shaInfo, "sign": sign, "timestamp": String(ts)]
            answer = httpPostJson(apiBase + OttaiConstants.epCgmAuthVerify, json(body), headers(ts: ts, apiBase: apiBase, profileOverride: profile), timeoutMs: 60_000)
        }
        guard let resp = answer else { return nil }
        let data = dataObject(resp)
        let answeredMac = OttaiConstants.canonicalSensorId(str(data, "mac"))
        if !answeredMac.isEmpty, answeredMac != canonical {
            lastFailure = CloudFailure(text: "cgmAuth/verify answered for a different sensor")
            return nil
        }
        let mat = V3AuthMaterial(authHost: str(data, "auth"), authFlag: str(data, "shaInfo"), keyB: str(data, "kb"),
                                 cf: str(data, "cf"), d: str(data, "d"), c: str(data, "c"))
        if !mat.ok, lastFailure == nil { lastFailure = CloudFailure(text: "cgmAuth/verify gave no auth answer") }
        return mat.ok ? mat : nil
    }

    // MARK: - bind after a server-assisted activation

    /// The bind answer has keyA. If the bind fails (it may have worked on an earlier try),
    /// ask for the sensor bound to the account. The server takes activatedAtMs as the start.
    static func bindAfterServerActivation(mac: String, deviceVersion: String, activatedAtMs: Int64,
                                         requestedContext: OttaiAccountContext? = nil) -> OttaiRegistry.DeviceMaterials? {
        let context = requestedContext ?? OttaiRegistry.accountContext()
        guard activatedAtMs > 0, OttaiRegistry.isCurrent(context) else { return nil }
        let canonical = OttaiConstants.canonicalSensorId(mac)
        let contract: BindContract = activeProfile(base()) == .globalPhone ? .globalM8 : base() == OttaiConstants.apiBase ? .v3 : .legacy
        if let current = boundSensorMaterials(canonical), materialsAreComplete(current), OttaiRegistry.isCurrent(context) {
            return current
        }
        guard OttaiRegistry.isCurrent(context), let binding = bindState(mac: canonical), OttaiRegistry.isCurrent(context) else { return nil }
        if case .other = binding {
            lastFailure = CloudFailure(text: "Another sensor remains linked to this account. Release it explicitly, then fetch this already-activated sensor again.", code: bizAlreadyBinding)
            return nil
        }
        var m: OttaiRegistry.DeviceMaterials?
        if let resp = bind(mac: canonical, deviceVersion: deviceVersion, userId: OttaiRegistry.loadUserId(), contract: contract, activeTimeMs: activatedAtMs) {
            m = toMaterials(mac: canonical, resp: resp).flatMap { $0.authKeys != nil ? $0 : nil }
        }
        guard OttaiRegistry.isCurrent(context) else { return nil }
        if m == nil {
            let bindFailure = lastFailure
            m = boundSensorMaterials(canonical)
            if m == nil { lastFailure = bindFailure ?? lastFailure ?? CloudFailure(text: "the bind gave no keys") }
        }
        if let current = m, current.activeTimeMs <= 0 { m?.activeTimeMs = activatedAtMs }
        guard OttaiRegistry.isCurrent(context), let m, materialsAreComplete(m) else {
            if lastFailure == nil { lastFailure = CloudFailure(text: "Sensor credentials or glucose calculation materials are incomplete. Retry fetching this sensor without activating it again.") }
            return nil
        }
        return m
    }

    static func materialsAreComplete(_ materials: OttaiRegistry.DeviceMaterials) -> Bool {
        let coefficients = materials.coefficients
        let tokens = materials.method.components(separatedBy: CharacterSet.alphanumerics.inverted).filter { !$0.isEmpty }
        let indices = tokens.filter { $0.first == "C" }.map { Int($0.dropFirst()) }
        return materials.authKeys != nil && !materials.method.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !coefficients.isEmpty && coefficients.allSatisfy(\.isFinite)
            && coefficients.count == materials.coefficient.split(separator: ",", omittingEmptySubsequences: false).count
            && indices.allSatisfy { $0.map { $0 >= 0 && $0 < coefficients.count } ?? false }
    }

    static func materialsReadyForSetup(_ materials: OttaiRegistry.DeviceMaterials, apiBase: String, profile: OttaiRegistry.SessionProfile) -> Bool {
        guard materialsAreComplete(materials) else { return false }
        if apiBase == OttaiConstants.apiBaseGlobal, profile == .globalPhone, materials.activeTimeMs <= 0 {
            return (try? OttaiGlobalActivation.preflight(materials: materials)) != nil
        }
        return true
    }

    /// The keys of this sensor if it is the one bound to the account. On Syai, authInfo
    /// gives the keys like in the app; its values win over getBindDevice (as in SyaiKit).
    private static func boundSensorMaterials(_ canonical: String) -> OttaiRegistry.DeviceMaterials? {
        guard var raw = bindDeviceResponse(), lastFailure == nil, var data = dataObject(raw) else { return nil }
        if let vo = data["cgmDeviceRespVO"] as? [String: Any] { data = vo }
        let boundId = OttaiConstants.canonicalSensorId(str(data, "mac"))
        guard !boundId.isEmpty, OttaiConstants.matchesCanonicalOrKnownNativeAlias(boundId, canonical) else { return nil }
        if isSyai, let auth = dataObject(OttaiSyaiClient.authInfo(mac: boundId)) {
            data.merge(auth.filter { !($0.value is NSNull) }) { _, fromAuthInfo in fromAuthInfo }
            raw = ["data": data]
        }
        guard let resp = parseDeviceResp(raw), let m = toMaterials(mac: boundId, resp: resp), m.authKeys != nil else { return nil }
        return m
    }

    /// GET deviceBind/getBindDevice, raw.
    private static func bindDeviceResponse() -> [String: Any]? {
        if isSyai { return OttaiSyaiClient.getBindDevice() }
        return httpGet(base() + OttaiConstants.epGetBindDevice, [:], headers(ts: now(), apiBase: base()))
    }

    /// "E2.0.3(V1.7.SH22601.3),STDRD" -> "V1.7.SH22601.3".
    static func deviceVersion(fromFirmware firmware: String) -> String {
        guard let open = firmware.firstIndex(of: "("),
              let close = firmware[open...].firstIndex(of: ")"),
              firmware.index(after: open) < close
        else { return firmware.trimmingCharacters(in: .whitespaces) }
        return String(firmware[firmware.index(after: open) ..< close])
    }

    // MARK: - unbind / list

    /// Uses only read-only sensor endpoints. Call on the serial cloud queue, not the main thread.
    static func accountSensors() -> Result<OttaiAccountSensorsSnapshot, Error> {
        let apiBase = base()
        let syai = isSyai
        let current: OttaiAccountSensors.Response
        if syai {
            let result = OttaiSyaiClient.getBindDeviceResult()
            current = .init(body: result.body, failure: result.failure?.displayText, requiresSignIn: result.failure?.requiresSignIn ?? false)
        } else {
            let result = httpGetResult(apiBase + OttaiConstants.epGetBindDevice, [:], headers(ts: now(), apiBase: apiBase))
            current = .init(body: result.body, failure: result.failure?.displayText, requiresSignIn: result.failure?.requiresSignIn ?? false)
        }
        if let failure = current.failure { return .failure(OttaiAccountSensorsError(message: failure, requiresSignIn: current.requiresSignIn)) }
        var history: OttaiAccountSensors.Response?
        if !syai {
            let result = httpGetResult(apiBase + OttaiConstants.epDeviceList, ["pageSize": "80", "pageNumber": "1"], headers(ts: now(), apiBase: apiBase))
            history = .init(body: result.body, failure: result.failure?.displayText, requiresSignIn: result.failure?.requiresSignIn ?? false)
        }
        return Result { try OttaiAccountSensors.snapshot(current: current, history: history) }
    }

    static func unbind(mac: String) -> Bool { unbind(mac: mac, headerOverride: nil) }

    /// Syai: unbindType 10 = wear time over, 13 = ended early (SyaiUnbindReason).
    static func syaiUnbindType(materials: OttaiRegistry.DeviceMaterials, acceptedMaxActiveMs: Int64, nowMs: Int64) -> Int {
        let lifetime = OttaiConstants.expectedLifetimeMs(cloudActiveExpireMs: materials.activeExpireTimeMs, acceptedMaxActiveMs: acceptedMaxActiveMs)
        return materials.activeTimeMs > 0 && materials.activeTimeMs + lifetime <= nowMs ? 10 : 13
    }

    private static func unbind(mac: String, headerOverride: ((Int64) -> [String: String])?) -> Bool {
        let canonical = OttaiConstants.canonicalSensorId(mac)
        if canonical.isEmpty { return false }
        if isSyai {
            let type = syaiUnbindType(materials: OttaiRegistry.loadMaterials(sensorId: canonical),
                                      acceptedMaxActiveMs: OttaiRegistry.loadAcceptedMaxActive(canonical), nowMs: now())
            return OttaiSyaiClient.unbind(mac: canonical, unbindType: type) != nil || (lastFailure?.code.caseInsensitiveEquals(bizEndUsing) ?? false)
        }
        let ts = now()
        let body: [String: Any] = ["mac": canonical, "deviceType": "cgm", "unbindType": 0]
        let requestHeaders = headerOverride?(ts) ?? headers(ts: ts, apiBase: base())
        guard let resp = httpPutJson(base() + OttaiConstants.epUnbind, json(body), requestHeaders) else { return false }
        let bizCode = anyToString(resp["code"])
        return bizCode.isEmpty || bizCode == "200" || bizCode.caseInsensitiveEquals("OK") || bizCode.caseInsensitiveEquals(bizEndUsing)
    }

    static func getBindDevice() -> DeviceResp? {
        bindDeviceResponse().flatMap { parseDeviceResp($0) }
    }

    // MARK: - account binding (xDrip only)

    // The Syai app shows only the sensor bound to the account, and an account has one bound sensor.
    enum BindState: Equatable {
        /// deviceId is the id of the bound device record, the one the Syai app shows.
        case thisSensor(deviceId: Int)
        case unbound
        case other(String)
    }

    /// Nil when the server could not be asked (see lastFailure).
    static func bindState(mac: String) -> BindState? {
        guard let resp = bindDeviceResponse(), lastFailure == nil else { return nil }
        let data = dataObject(resp)
        let vo = (data?["cgmDeviceRespVO"] as? [String: Any]) ?? data
        let bound = OttaiConstants.canonicalSensorId(str(vo, "mac"))
        if bound.isEmpty { return .unbound }
        return OttaiConstants.matchesCanonicalOrKnownNativeAlias(bound, mac) ? .thisSensor(deviceId: Int(longLoose(vo, "id"))) : .other(bound)
    }

    /// Binds the sensor for good. The server takes activeTime as the sensor start, so it must be the real one.
    static func bindPermanently(mac: String, materials: OttaiRegistry.DeviceMaterials) -> Bool {
        guard materials.activeTimeMs > 0 else { lastFailure = CloudFailure(text: "activation time not known yet"); return false }
        let version = materials.deviceVersion.isEmpty ? syaiMaterialBindDeviceVersion : materials.deviceVersion
        _ = bind(mac: mac, deviceVersion: version, userId: OttaiRegistry.loadUserId(),
                 contract: activeProfile(base()) == .globalPhone ? .globalM8 : .legacy, activeTimeMs: materials.activeTimeMs)
        return lastFailure == nil
    }

    /// Unbinds the sensor if the account still has it bound. Same as JugglucoNG on sensor removal:
    /// a sensor left bound blocks the next one.
    static func releaseIfBound(mac: String) -> Bool {
        guard isSignedIn, case .thisSensor? = bindState(mac: mac) else { return false }
        return unbind(mac: mac)
    }

    static func listDevices(pageSize: Int = 80, pageNumber: Int = 1) -> [DeviceSummary] {
        let ts = now()
        guard let resp = httpGet(base() + OttaiConstants.epDeviceList,
                                 ["pageSize": String(pageSize), "pageNumber": String(pageNumber)],
                                 headers(ts: ts, apiBase: base())),
              let data = dataObject(resp) else { return [] }
        let items = (data["items"] as? [[String: Any]]) ?? (data["list"] as? [[String: Any]]) ?? (data["records"] as? [[String: Any]]) ?? []
        return items.compactMap { o in
            let mac = str(o, "mac")
            if mac.isEmpty { return nil }
            var version = str(o, "deviceVersion")
            if version.isEmpty { version = str(o["cgmDeviceRespVO"] as? [String: Any], "deviceVersion") }
            return DeviceSummary(mac: mac, serialNo: str(o, "serialNo"), deviceType: str(o, "deviceType"),
                                 deviceVersion: version, bindTime: longLoose(o, "bindTime"), unbindTime: longLoose(o, "unbindTime"))
        }
    }

    // MARK: - parse + decrypt

    private static func parseDeviceResp(_ resp: [String: Any], requireKeyA: Bool = true) -> DeviceResp? {
        guard let data = dataObject(resp) else { return nil }
        let vo = (data["cgmDeviceRespVO"] as? [String: Any]) ?? data
        let mvo = (data["cgmDeviceMethodVO"] as? [String: Any]) ?? vo
        let keyA = str(vo, "keyA")
        if requireKeyA && keyA.isEmpty { return nil }
        func pick(_ key: String) -> String {
            let m = str(mvo, key)
            if !m.isEmpty { return m }
            let v = str(vo, key)
            return v.isEmpty ? str(data, key) : v
        }
        func pickTime(_ key: String) -> Int64 { let m = longLoose(mvo, key); return m != 0 ? m : longLoose(vo, key) }
        return DeviceResp(
            mac: str(vo, "mac"), keyA: keyA, method: pick("method"), coefficient: pick("coefficient"),
            produceTime: longLoose(vo, "produceTime"), methodUpdateTime: pickTime("methodUpdateTime"), coeffUpdateTime: pickTime("coeffUpdateTime"),
            activeTime: longLoose(vo, "activeTime"), activeExpireTime: longLoose(vo, "activeExpireTime"),
            preheatPeriodTime: longLoose(vo, "preheatPeriodTime"), retainTime: longLoose(vo, "retainTime"),
            deviceVersion: str(vo, "deviceVersion"), deviceId: Int(longLoose(vo, "id")),
            gracePeriodTime: longLoose(vo, "gracePeriodTime"),
            calibrationValueK: Double(pick("calibrationValueK")), calibrationValueB: Double(pick("calibrationValueB"))
        )
    }

    /// Decrypt the sensor keys from the cloud answer with the account secret key.
    static func toMaterials(mac: String, resp: DeviceResp) -> OttaiRegistry.DeviceMaterials? {
        let secret = OttaiRegistry.loadGlucoseSecretKey()
        if secret.isEmpty { return nil }
        let canonical = OttaiConstants.canonicalSensorId(mac)
        guard let keyAPlain = OttaiCrypto.decryptKeyA(base64KeyA: resp.keyA, glucoseSecretKey: secret, produceTime: String(resp.produceTime), mac: canonical) else { return nil }
        if OttaiCrypto.parseAuthKeys(keyAPlain) == nil { return nil }
        let methodPlain = resp.method.isEmpty ? "" : (OttaiCrypto.decryptMethod(base64Method: resp.method, glucoseSecretKey: secret, methodUpdateTime: String(resp.methodUpdateTime), mac: canonical) ?? "")
        let coeffPlain = resp.coefficient.isEmpty ? "" : (OttaiCrypto.decryptCoefficient(base64Coeff: resp.coefficient, glucoseSecretKey: secret, coeffUpdateTime: String(resp.coeffUpdateTime), mac: canonical) ?? "")
        return OttaiRegistry.DeviceMaterials(
            keyAHex: keyAPlain,
            method: OttaiMethodDefaults.resolve(method: methodPlain, coefficient: coeffPlain),
            coefficient: coeffPlain,
            activeTimeMs: normalizeOttaiActiveTimeMs(resp.activeTime),
            deviceVersion: resp.deviceVersion,
            deviceId: resp.deviceId,
            activeExpireTimeMs: resp.activeExpireTime,
            retainTimeMs: resp.retainTime,
            preheatPeriodMs: resp.preheatPeriodTime,
            gracePeriodMs: resp.gracePeriodTime,
            calibrationValueK: resp.calibrationValueK, calibrationValueB: resp.calibrationValueB
        )
    }

    // MARK: - get and save the keys of one sensor (same as fetchOttaiMaterials in JugglucoNG)

    /// After login, get the keys for [cloudId] and save them. Order: saved keys -> an open
    /// bind after a server activation -> check by mac -> the sensor bound to the account ->
    /// a short bind and unbind (old Syai / Global sensor). A new V3 sensor is never bound
    /// before activation: it gets `.readyForServerActivation`. Not on the main thread.
    static func fetchAndSaveMaterials(cloudId: String, requestedContext: OttaiAccountContext? = nil) -> MaterialsOutcome {
        let context = requestedContext ?? OttaiRegistry.accountContext()
        func isCurrent() -> Bool { OttaiRegistry.isCurrent(context) }
        let canonical = OttaiConstants.canonicalSensorId(cloudId)
        if canonical.isEmpty || !isCurrent() { return .failed }
        if OttaiRegistry.loadPendingBind(canonical) == 0,
           materialsReadyForSetup(OttaiRegistry.loadMaterials(sensorId: canonical), apiBase: context.apiBase,
                                  profile: activeProfile(context.apiBase)) { return .saved }
        func save(_ m: OttaiRegistry.DeviceMaterials) -> MaterialsOutcome {
            isCurrent() && materialsAreComplete(m) && OttaiRegistry.saveMaterials(sensorId: canonical, m) ? .saved : .failed
        }

        if let materials = boundSensorMaterials(canonical),
           materialsReadyForSetup(materials, apiBase: context.apiBase, profile: activeProfile(context.apiBase)) {
            let outcome = save(materials)
            if outcome == .saved, materials.activeTimeMs > 0 {
                OttaiRegistry.clearPendingBind(canonical)
                OttaiRegistry.clearActivationCheckpoint(canonical)
                OttaiRegistry.setActivationAttempted(canonical, false)
                OttaiRegistry.saveActivationStatus(canonical, nil)
            }
            return outcome
        }

        let pendingBindAtMs = OttaiRegistry.loadPendingBind(canonical)
        if pendingBindAtMs > 0 {
            guard let checkpoint = OttaiRegistry.loadActivationCheckpoint(canonical), checkpoint.confirmed,
                  checkpoint.apiBase == context.apiBase, checkpoint.userID == context.userId else {
                lastFailure = CloudFailure(text: "A previous activation is not confirmed for this account. No bind or repeat activation was attempted.")
                return .failed
            }
            guard isCurrent(), let m = bindAfterServerActivation(mac: canonical, deviceVersion: serverActivationBindVersion(canonical), activatedAtMs: pendingBindAtMs, requestedContext: context) else { return .failed }
            let outcome = save(m)
            if outcome == .saved { OttaiRegistry.clearPendingBind(canonical); OttaiRegistry.clearActivationCheckpoint(canonical) }
            return outcome
        }

        var firstFailure: CloudFailure?
        func remember() { if firstFailure == nil { firstFailure = lastFailure } }

        if let v = validateForSetup(mac: canonical) {
            if !v.device.keyA.isEmpty, let m = toMaterials(mac: canonical, resp: v.device), m.authKeys != nil {
                if activeProfile(base()) == .globalPhone, m.activeTimeMs <= 0 {
                    guard isCurrent(), let binding = bindState(mac: canonical), isCurrent() else { return .failed }
                    if case .other = binding {
                        lastFailure = CloudFailure(text: "Another sensor remains linked to this account. Finish using it and release it explicitly before starting a new sensor.", code: bizAlreadyBinding)
                        return .failed
                    }
                    do { try OttaiGlobalActivation.preflight(materials: m) }
                    catch { lastFailure = CloudFailure(text: error.localizedDescription); return .failed }
                }
                return save(m)
            }
            if v.requiresV3Bind {
                // Maybe already started and bound, e.g. by the official app.
                if let m = boundSensorMaterials(canonical) { return save(m) }
                guard isCurrent(), let binding = bindState(mac: canonical), isCurrent() else { return .failed }
                if case .other = binding {
                    lastFailure = CloudFailure(text: "Another sensor is still linked to this account. Release it explicitly before starting the new sensor.", code: bizAlreadyBinding)
                    return .failed
                }
                OttaiRegistry.setV3CredentialBootstrapPending(canonical, true)
                // An old Activate tap must not start the sensor; the user taps again.
                OttaiRegistry.setActivationAttempted(canonical, false)
                lastFailure = nil
                return .readyForServerActivation
            }
        }
        remember()

        if let m = boundSensorMaterials(canonical) { return save(m) }
        remember()

        // Never perform an automatic temporary bind/unbind using the native Global account.
        // Its read-only materials flow must be used, preserving the live sensor's binding.
        if isCurrent(), activeProfile(base()) != .globalPhone,
           let version = materialBindDeviceVersion(selectedDeviceVersion: nil, failureCode: firstFailure?.code),
           let resp = bindForMaterials(mac: canonical, deviceVersion: version),
           let m = toMaterials(mac: canonical, resp: resp), m.authKeys != nil {
            return save(m)
        }
        if lastFailure == nil { lastFailure = firstFailure }
        return .failed
    }

    /// From the V3 check, or from the firmware (the transmitter saves it there).
    static func serverActivationBindVersion(_ sensorId: String) -> String {
        OttaiRegistry.loadLastValidatedDeviceVersion(sensorId: sensorId) ?? OttaiRegistry.loadMaterials(sensorId: sensorId).deviceVersion
    }

    // MARK: - website API (email login and sign-up)

    private static let webApp = "ottai-seas"
    private static let webDeviceId = "8"
    private static let webAesKey = "miH5ngQ7z4NZU3JgZFq87Gg6v1Y7YJm9"
    private static let webFingerprint = "0123456789abcdef0123456789abcdef01234567"
    private static let webAppSyai = "cgm"
    private static let webFingerprintSyai = "90507337afdab98e443d3ec8fcccb672"

    private static func isSyaiWeb(_ webBase: String) -> Bool { webBase.contains("syai") }
    private static func webAppFor(_ webBase: String) -> String { isSyaiWeb(webBase) ? webAppSyai : webApp }
    private static func webSign(_ parts: String...) -> String { md5Hex(parts.joined() + seed) }

    private static func webHeaders(_ webBase: String, ts: Int64) -> [String: String] {
        if isSyaiWeb(webBase) {
            return ["appName": webAppSyai, "timestamp": String(ts), "deviceFingerprinting": webFingerprintSyai,
                    "country": "US", "region": "Americas", "ua": "Android", "versionCode": "5",
                    "traceId": "trace_\(ts)", "language": "en", "timezone": "-18000"]
        }
        return ["appName": webApp, "timestamp": String(ts), "deviceId": webDeviceId, "deviceFingerprinting": webFingerprint,
                "region": "Europe", "ua": "web", "versionCode": "253201", "traceId": "trace_\(ts)",
                "language": "en", "timezone": "0", "X-Canary-Mode": "OFF", "country": "RU"]
    }

    private static func webEncrypt(_ plainJson: String) -> String {
        guard let out = OttaiCrypto.aesECB(.encrypt, key: Array(webAesKey.utf8), data: Array(plainJson.utf8), pkcs7Padded: true) else { return "" }
        return Data(out).base64EncodedString()
    }

    private static func getWebApiToken(_ webBase: String) -> String? {
        for attempt in 0 ..< 2 {
            let ts = now()
            let reply = httpGetResult("\(webBase)/user/apiToken", ["signature": webSign(webAppFor(webBase), String(ts))], webHeaders(webBase, ts: ts))
            lastFailure = reply.failure
            if reply.failure == nil, let tok = str(reply.body, "data").nilIfEmpty { return tok }
            if attempt == 0 { usleep(900_000) }
        }
        return nil
    }

    private static func webPostRetry(_ webBase: String, _ path: String, buildBody: (_ apiToken: String, _ ts: Int64) -> [String: Any]) -> [String: Any]? {
        for attempt in 0 ..< 5 {
            guard let apiToken = getWebApiToken(webBase) else { if lastFailure == nil { lastFailure = CloudFailure(text: "apiToken failed", stage: "Web API token") }; return nil }
            let ts = now()
            let reply = httpPostJsonResult("\(webBase)\(path)", json(buildBody(apiToken, ts)), webHeaders(webBase, ts: ts))
            lastFailure = reply.failure
            guard let resp = reply.body else { return nil }
            if !anyToString(resp["code"]).caseInsensitiveEquals("User_SignatureInvalid") { return reply.failure == nil ? resp : nil }
            if attempt < 4 { usleep(500_000) }
        }
        return nil
    }

    static func mailLogin(email: String, password: String, webBase: String = OttaiConstants.webBaseOttai) -> LoginResult? {
        let em = email.trimmingCharacters(in: .whitespaces)
        if em.isEmpty || password.isEmpty { lastFailure = CloudFailure(text: "email/password required"); return nil }
        if webBase == OttaiConstants.webBaseOttai { return globalMailLogin(email: em, password: password) }
        OttaiRegistry.clearAccountSession()
        if isSyaiWeb(webBase) { return OttaiSyaiClient.login(email: em, password: password) }
        let encInfo = webEncrypt(json(["username": em, "password": password]))
        guard let resp = webPostRetry(webBase, "/user/login/thirdLoginByPassword", buildBody: { apiToken, ts in
            ["uuid": UUID().uuidString.replacingOccurrences(of: "-", with: ""), "encryptInfo": encInfo, "apiToken": apiToken, "source": 5,
             "signature": webSign(webApp, webDeviceId, String(ts), apiToken, em, password)]
        }) else { return nil }
        return upgradeWebLogin(resp, password: password, webBase: webBase)
    }

    /// Global uses the official native email contract, not the legacy web-to-WATCH upgrade.
    private static func globalMailLogin(email: String, password: String) -> LoginResult? {
        guard let requested = OttaiRegistry.beginGlobalLogin() else {
            lastFailure = CloudFailure(text: "Account region changed. Open Sign in again.", stage: "Global sign-in"); return nil
        }
        let owner = OttaiRegistry.loadOrCreateGlobalHeaderDeviceId()
        let reply = OttaiGlobalContract.authenticate(email: email, password: password, deviceID: owner,
            deviceModel: OttaiCloudUploader.deviceModel, send: { request in
                if request.method == "GET" { return httpGetResult(request.url, request.query, request.headers) }
                return httpPostJsonResult(request.url, json(request.body ?? [:]), request.headers)
            })
        switch reply {
        case .failure(let failure): lastFailure = failure; return nil
        case .success(let login):
            guard OttaiRegistry.commitGlobalLogin(login, email: email, requested: requested) else {
                lastFailure = CloudFailure(text: "Account or region changed. Sign in again.", stage: "Global sign-in"); return nil
            }
            lastFailure = nil
            return login
        }
    }

    static func sendMail(email: String, type: String = "SIGN_UP", webBase: String = OttaiConstants.webBaseOttai) -> String? {
        let em = email.trimmingCharacters(in: .whitespaces)
        guard let resp = webPostRetry(webBase, "/user/mail/sendMail", buildBody: { apiToken, ts in
            ["type": type, "isSend": 1, "email": em, "apiToken": apiToken, "signature": webSign(webAppFor(webBase), String(ts), em, apiToken)]
        }) else { return nil }
        if !anyToString(resp["code"]).caseInsensitiveEquals("OK") { return nil }
        return str(dataObject(resp), "key").nilIfEmpty
    }

    static func signUp(email: String, password: String, profileName: String, requestId: String, validCode: String, webBase: String = OttaiConstants.webBaseOttai) -> LoginResult? {
        OttaiRegistry.clearAccountSession()
        let em = email.trimmingCharacters(in: .whitespaces)
        if isSyaiWeb(webBase) { return syaiSignUp(em: em, password: password, requestId: requestId, validCode: validCode, webBase: webBase) }
        let encInfo = webEncrypt(json(["email": em, "password": password, "profileName": profileName]))
        guard let resp = webPostRetry(webBase, "/user/mail/signUp", buildBody: { apiToken, ts in
            ["apiToken": apiToken, "encryptInfo": encInfo, "requestId": requestId, "validCode": validCode,
             "recommendFlag": false, "country": "RU", "language": "en", "signature": webSign(webApp, String(ts), requestId, em, validCode)]
        }) else { return nil }
        return upgradeWebLogin(resp, password: password, webBase: webBase)
    }

    private static func syaiSignUp(em: String, password: String, requestId: String, validCode: String, webBase: String) -> LoginResult? {
        guard let verify = webPostRetry(webBase, "/user/mail/verifyMail", buildBody: { _, ts in
            ["type": "SIGN_UP", "validCode": validCode, "requestId": requestId, "email": em, "signature": webSign(webAppSyai, String(ts), requestId, em, validCode)]
        }), anyToString(verify["code"]).caseInsensitiveEquals("OK") else { return nil }
        let encInfo = webEncrypt(json(["email": em, "password": password]))
        guard webPostRetry(webBase, "/user/mail/signUp", buildBody: { _, ts in
            ["encryptInfo": encInfo, "requestId": requestId, "signature": webSign(webAppSyai, String(ts), requestId, em)]
        }) != nil else { return nil }
        return OttaiSyaiClient.login(email: em, password: password)
    }

    static func webBaseToMobile(_ webBase: String) -> String {
        webBase.contains("syai") ? OttaiConstants.apiBaseSyai : OttaiConstants.apiBaseGlobal
    }

    private static func upgradeWebLogin(_ response: [String: Any], password: String, webBase: String) -> LoginResult? {
        let mobileBase = webBaseToMobile(webBase)
        let reply = OttaiLoginFlow.upgrade(webResponse: response,
            readProfile: { token in webProfile(webBase, accessToken: token) },
            login: { name, token in nativePasswordLogin(account: name, password: password, base: mobileBase, authorization: token) },
            retryDelay: { usleep(500_000) })
        return finishMobileLogin(reply, apiBase: mobileBase)
    }

    private static func webProfile(_ webBase: String, accessToken: String) -> Result<[String: Any], CloudFailure> {
        let ts = now()
        var headers = webHeaders(webBase, ts: ts)
        headers["Authorization"] = "Bearer \(accessToken)"
        let reply = httpGetResult("\(webBase)/user/getUser", [:], headers)
        if let failure = reply.failure { return .failure(failure) }
        guard let data = dataObject(reply.body) else { return .failure(CloudFailure(text: "Account profile lookup returned no data.")) }
        return .success(data)
    }

    // MARK: - HTTP

    private static func httpGet(_ base: String, _ query: [String: String], _ headers: [String: String]) -> [String: Any]? {
        let qs = query.map { "\(enc($0.key))=\(enc($0.value))" }.joined(separator: "&")
        let url = qs.isEmpty ? base : "\(base)?\(qs)"
        return request("GET", url: url, body: nil, headers: headers)
    }

    private static func httpPostJsonResult(_ url: String, _ body: String, _ headers: [String: String]) -> RequestResult {
        var h = headers
        h["Content-Type"] = "application/json;charset=UTF-8"
        return requestResult("POST", url: url, body: body, headers: h)
    }

    private static func httpPostJson(_ url: String, _ body: String, _ headers: [String: String], timeoutMs: Int = timeoutMs) -> [String: Any]? {
        var h = headers; h["Content-Type"] = "application/json;charset=UTF-8"
        return request("POST", url: url, body: body, headers: h, timeoutMs: timeoutMs)
    }

    private static func httpPutJson(_ url: String, _ body: String, _ headers: [String: String]) -> [String: Any]? {
        var h = headers; h["Content-Type"] = "application/json;charset=UTF-8"
        return request("PUT", url: url, body: body, headers: h)
    }

    struct RequestResult {
        let body: [String: Any]?
        let failure: CloudFailure?
    }

    private static func httpGetResult(_ base: String, _ query: [String: String], _ headers: [String: String]) -> RequestResult {
        let qs = query.map { "\(enc($0.key))=\(enc($0.value))" }.joined(separator: "&")
        return requestResult("GET", url: qs.isEmpty ? base : "\(base)?\(qs)", body: nil, headers: headers)
    }

    private static func request(_ method: String, url: String, body: String?, headers: [String: String], timeoutMs: Int = timeoutMs) -> [String: Any]? {
        let result = requestResult(method, url: url, body: body, headers: headers, timeoutMs: timeoutMs)
        lastFailure = result.failure
        return result.body
    }

    private static func requestResult(_ method: String, url: String, body: String?, headers: [String: String], timeoutMs: Int = timeoutMs) -> RequestResult {
        do {
            let reply = try OttaiRegionalTransport.request(method, url: url, body: body, headers: headers) { verb, target, payload, common in
                try rawRequest(verb, url: target, body: payload, headers: common, timeoutMs: timeoutMs)
            }
            let result = decodeRequestResult(status: reply.status, body: reply.json)
            return .init(body: result.body, failure: result.failure?.contextualized(stage: requestStage(url), origin: reply.origin.rawValue))
        } catch let error as OttaiSecureTransportFailure {
            return .init(body: nil, failure: CloudFailure(text: error.diagnostic, code: error.businessCode, httpStatus: error.httpStatus).contextualized(stage: requestStage(url), origin: "transport"))
        } catch let error as CloudFailure {
            return .init(body: nil, failure: error.contextualized(stage: requestStage(url)))
        } catch {
            return .init(body: nil, failure: CloudFailure(text: "Secure request failed.").contextualized(stage: requestStage(url)))
        }
    }

    static func requestStage(_ url: String) -> String {
        guard let components = URLComponents(string: url) else { return "Request" }
        let path = components.path
        let mobile = path.hasPrefix("/cgm/app/server/")
        if path.hasSuffix("/apiToken") { return mobile ? "Mobile API token" : "Web API token" }
        if path.hasSuffix("/thirdLoginByPassword") { return "Email sign-in" }
        if path.hasSuffix("/getUser") { return "Account profile" }
        if path.hasSuffix("/accountLogin") { return "Mobile sign-in" }
        if path.hasSuffix("/variousLogin") { return "Global email sign-in" }
        if path.hasSuffix("/getBindDevice") { return "Current account sensor" }
        if path.hasSuffix("/deviceBind/list") { return "Account sensor history" }
        return "Account request"
    }

    private static func rawRequest(_ method: String, url: String, body: String?, headers: [String: String], timeoutMs: Int) throws -> OttaiNetSecurity.Reply {
        if url.hasPrefix("https://seas.ottai.com/cgm/security/app/server/") {
            return try OttaiSecureHTTP.send(method, url: url, body: body, headers: headers, timeoutMs: timeoutMs)
        }
        guard let u = URL(string: url) else { throw CloudFailure(text: "bad url") }
        var req = URLRequest(url: u)
        req.httpMethod = method
        req.timeoutInterval = TimeInterval(timeoutMs) / 1000.0
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        if let body = body { req.httpBody = body.data(using: .utf8) }

        let sem = DispatchSemaphore(value: 0)
        var outData: Data?
        var outCode = -1
        var outErr: Error?
        let task = URLSession.shared.dataTask(with: req) { data, response, error in
            outData = data
            outErr = error
            if let http = response as? HTTPURLResponse { outCode = http.statusCode }
            sem.signal()
        }
        task.resume()
        guard sem.wait(timeout: .now() + .milliseconds(timeoutMs + 5_000)) == .success else {
            task.cancel()
            throw CloudFailure(text: "Network request timed out.")
        }
        if outErr != nil { throw CloudFailure(text: "Network request failed.") }
        let text = outData.flatMap { String(data: $0, encoding: .utf8) } ?? ""
        let jsonObj = text.isEmpty ? nil : (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any]
        return .init(status: outCode, json: jsonObj)
    }

    static func decodeRequestResult(status: Int, body jsonObj: [String: Any]?) -> RequestResult {
        let bizCode = anyToString(jsonObj?["code"])
        let bizMsg = anyToString(jsonObj?["message"]).nilIfEmpty ?? anyToString(jsonObj?["msg"]).nilIfEmpty ?? anyToString(jsonObj?["detailMessage"])
        let bizOk = bizCode.isEmpty || bizCode == "200" || bizCode.caseInsensitiveEquals("OK")
        let failure: CloudFailure? = !(200 ... 299).contains(status) || !bizOk
            ? CloudFailure(text: "http=\(status) biz=\(bizCode) \(String(bizMsg.prefix(120)))".trimmingCharacters(in: .whitespaces), code: bizCode, httpStatus: status)
            : nil
        return RequestResult(body: jsonObj, failure: failure)
    }

    // MARK: - JSON helpers

    private static func json(_ obj: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: obj, options: []) else { return "{}" }
        return String(data: data, encoding: .utf8) ?? "{}"
    }

    private static func dataObject(_ resp: [String: Any]?) -> [String: Any]? {
        (resp?["data"] as? [String: Any]) ?? (resp?["result"] as? [String: Any])
    }

    private static func str(_ dict: [String: Any]?, _ key: String) -> String {
        anyToString(dict?[key])
    }

    private static func longLoose(_ dict: [String: Any]?, _ key: String) -> Int64 {
        guard let v = dict?[key] else { return 0 }
        if let n = v as? NSNumber { return n.int64Value }
        if let s = v as? String { return Int64(s) ?? 0 }
        return 0
    }

    private static func anyToString(_ any: Any?) -> String {
        guard let any = any else { return "" }
        if let s = any as? String { return s == "null" ? "" : s }
        if let n = any as? NSNumber { return n.stringValue }
        return ""
    }

    private static func enc(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .urlQueryValueAllowed) ?? s
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
    func caseInsensitiveEquals(_ other: String) -> Bool { caseInsensitiveCompare(other) == .orderedSame }
}

private extension CharacterSet {
    static let urlQueryValueAllowed: CharacterSet = {
        var cs = CharacterSet.urlQueryAllowed
        cs.remove(charactersIn: "&=?+")
        return cs
    }()
}
