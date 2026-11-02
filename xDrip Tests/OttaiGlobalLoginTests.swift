import XCTest
@testable import xdrip

final class OttaiGlobalLoginTests: XCTestCase {
    private let owner = "ottai-seas:a:g:ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
    private let timestamp: Int64 = 1_760_000_000_123
    private let email = "fixture@example.invalid"
    private let password = "Only-for-public-fixture-123!"
    private typealias Reply = OttaiCloudClient.RequestResult
    private var candidate: OttaiCloudClient.LoginResult { .init(userId: "42", accessToken: "fixture-native-token", glucoseSecretKey: "fixture-root-key") }
    private var goodReplies: [Reply] { [
        .init(body: ["code": "OK", "data": "fixture-api-token"], failure: nil),
        .init(body: ["code": "OK", "data": ["userId": 42, "accessToken": "fixture-native-token", "glucoseSecretKey": "fixture-root-key"]], failure: nil),
        .init(body: ["code": "OK", "data": ["mac": "AABBCCDDEEFF"]], failure: nil),
        .init(body: ["code": "OK", "data": ["items": []]], failure: nil)
    ] }

    private func authenticate(_ replies: [Reply], observe: (OttaiGlobalContract.Request, Int) -> Void = { _, _ in }) -> Result<OttaiCloudClient.LoginResult, OttaiCloudClient.CloudFailure> {
        var index = 0
        return OttaiGlobalContract.authenticate(email: email, password: password, deviceID: owner, deviceModel: "Fixture device", send: { request in
            observe(request, index)
            guard index < replies.count else { XCTFail("Unexpected extra request"); return .init(body: nil, failure: .init(text: "Unexpected extra request")) }
            defer { index += 1 }
            return replies[index]
        }, clock: { self.timestamp })
    }

    private func defaults(_ work: (UserDefaults) throws -> Void) throws {
        let suite = "OttaiGlobalLoginTests." + UUID().uuidString
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(OttaiConstants.apiBaseGlobal, forKey: "ottai_api_base")
        try work(defaults)
    }

    func testOfficialURLDTOAndIndependentOpenSSLVector() throws {
        XCTAssertEqual(OttaiGlobalContract.loginURL, "https://seas.ottai.com/cgm/app/server/user/login/variousLogin")
        XCTAssertEqual(OttaiCloudClient.signForProfile(.globalPhone, deviceId: owner, ts: timestamp), "3272fb39aa3780046d9acbcd4cf85e8d")
        let signature = OttaiCloudClient.signForProfile(.globalPhone, deviceId: owner, ts: timestamp, "fixture-api-token", email, password)
        XCTAssertEqual(signature, "e33f72a1b8a45b827af4c52a81390c26")
        let body = try XCTUnwrap(OttaiGlobalContract.passwordBody(email: email, password: password, apiToken: "fixture-api-token", signature: signature))
        XCTAssertEqual(Set(body.keys), Set(["encryptInfo", "apiToken", "signature", "type", "phoneCode"]))
        XCTAssertEqual(body["type"] as? String, "2")
        XCTAssertEqual(body["phoneCode"] as? String, "")
        XCTAssertEqual(body["encryptInfo"] as? String, "Qpkz1BFBblAQvjg/STUUV30UgPhp91VauXazwylXdSndxJm8csX7pjdX1v/cnJemmbZX7bI/JWDPtIjrgnM6QVYrv1jQZ7l4KUNkDq8QQQsAQ8i+qeOR51dK0xtNpapV")
    }

    func testFullFlowUsesOneNativePasswordPostAndSameIdentityForValidation() throws {
        var calls: [OttaiGlobalContract.Request] = []
        let login = try authenticate(goodReplies) { request, _ in calls.append(request) }.get()
        XCTAssertEqual(login.userId, "42")
        XCTAssertEqual(calls.map(\.method), ["GET", "POST", "GET", "GET"])
        XCTAssertEqual(calls.map(\.url), [OttaiConstants.apiBaseGlobal + OttaiConstants.epApiToken, OttaiGlobalContract.loginURL,
            OttaiConstants.apiBaseGlobal + OttaiConstants.epGetBindDevice, OttaiConstants.apiBaseGlobal + OttaiConstants.epDeviceList])
        for (index, request) in calls.enumerated() {
            XCTAssertEqual(request.headers["deviceId"], owner)
            XCTAssertEqual(request.headers["appName"], "ottai-seas")
            XCTAssertEqual(request.headers["applicationType"], "ottai_seas")
            XCTAssertEqual(request.headers["packageName"], "com.ottai.seas")
            XCTAssertEqual(request.headers["Authorization"], index < 2 ? nil : "fixture-native-token")
            XCTAssertEqual(request.headers["timestamp"], String(timestamp))
        }
    }

    func testTokenHTTPFailureOrMalformedDataNeverSendsPassword() {
        for first in [Reply(body: ["data": "do-not-accept"], failure: .init(text: "failed", httpStatus: 500)),
                      Reply(body: ["data": ["apiToken": "unsupported"]], failure: nil), Reply(body: ["data": ""], failure: nil)] {
            var count = 0
            XCTAssertThrowsError(try authenticate([first]) { _, _ in count += 1 }.get())
            XCTAssertEqual(count, 1)
        }
    }

    func testPasswordFailureHasNoRetryAndNoFreeFormServerMessage() {
        var replies = goodReplies
        replies[1] = .init(body: ["data": ["accessToken": "must-not-use"]], failure: .init(text: "password=\(password) token=unsafe", code: "User_PasswordInvalid", httpStatus: 400, origin: "authenticated"))
        var count = 0
        XCTAssertThrowsError(try authenticate(replies) { _, _ in count += 1 }.get()) { error in
            let failure = error as? OttaiCloudClient.CloudFailure
            XCTAssertEqual(failure?.code, "User_PasswordInvalid")
            XCTAssertFalse(failure?.displayText.contains(self.password) ?? true)
            XCTAssertFalse(failure?.displayText.contains("unsafe") ?? true)
        }
        XCTAssertEqual(count, 2)
    }

    func testCompleteCandidateRequiresUserIDBeforeAnySensorRead() {
        var replies = goodReplies
        replies[1] = .init(body: ["data": ["accessToken": "token", "glucoseSecretKey": "root"]], failure: nil)
        var count = 0
        XCTAssertThrowsError(try authenticate(replies) { _, _ in count += 1 }.get())
        XCTAssertEqual(count, 2)
    }

    func testRejectedOrMalformedBindingCannotValidateCandidate() {
        for current in [Reply(body: ["data": ["mac": "AABBCCDDEEFF"]], failure: .init(text: "unauthorized", code: "AuthFailed_TokenInvalid", httpStatus: 401)),
                        Reply(body: ["data": ["unsupported": true]], failure: nil)] {
            var replies = goodReplies; replies[2] = current
            var count = 0
            XCTAssertThrowsError(try authenticate(replies) { _, _ in count += 1 }.get())
            XCTAssertEqual(count, 3)
        }
    }

    func testHistoryFailureOrMalformedHistoryCannotValidateCandidate() {
        for history in [Reply(body: ["data": ["items": []]], failure: .init(text: "unavailable", httpStatus: 500)),
                        Reply(body: ["data": ["notItems": []]], failure: nil),
                        Reply(body: ["data": ["items": [[:]]]], failure: nil)] {
            var replies = goodReplies; replies[3] = history
            XCTAssertThrowsError(try authenticate(replies).get())
        }
    }

    func testValidEmptyAccountStillAuthenticates() throws {
        var replies = goodReplies; replies[2] = .init(body: ["code": "OK", "data": NSNull()], failure: nil)
        XCTAssertTrue(try authenticate(replies).get().ok)
    }

    func testCandidateNotPersistedDuringAnyRequestAndCommitPreservesBLE() throws {
        try defaults { defaults in
            defaults.set("old-token", forKey: "ottai_access_token")
            defaults.set("old-root", forKey: "ottai_glucose_secret_key")
            defaults.set("old-user", forKey: "ottai_user_id")
            defaults.set("WATCH", forKey: "ottai_session_profile")
            defaults.set("old@example.invalid", forKey: "ottai_account_login")
            defaults.set("sensor-keys", forKey: "ottai_keya_AABBCCDDEEFF")
            defaults.set(123, forKey: "ottai_pending_bind_AABBCCDDEEFF")
            let context = try XCTUnwrap(OttaiRegistry.beginGlobalLogin(in: defaults))
            let candidate = try authenticate(goodReplies) { _, _ in
                XCTAssertEqual(defaults.string(forKey: "ottai_access_token"), "old-token")
                XCTAssertEqual(defaults.string(forKey: "ottai_glucose_secret_key"), "old-root")
                XCTAssertEqual(defaults.string(forKey: "ottai_account_login"), "old@example.invalid")
            }.get()
            XCTAssertTrue(OttaiRegistry.commitGlobalLogin(candidate, email: email, requested: context, in: defaults))
            XCTAssertEqual(defaults.string(forKey: "ottai_access_token"), "fixture-native-token")
            XCTAssertEqual(OttaiRegistry.loadSessionProfile(in: defaults), .globalPhone)
            XCTAssertEqual(defaults.string(forKey: "ottai_account_login"), email)
            XCTAssertEqual(defaults.string(forKey: "ottai_keya_AABBCCDDEEFF"), "sensor-keys")
            XCTAssertEqual(defaults.integer(forKey: "ottai_pending_bind_AABBCCDDEEFF"), 123)
            XCTAssertFalse(defaults.dictionaryRepresentation().values.contains { ($0 as? String) == password })
        }
    }

    func testFailedCandidateKeepsPriorAccountAndBLEState() throws {
        try defaults { defaults in
            defaults.set("old-token", forKey: "ottai_access_token")
            defaults.set("sensor-keys", forKey: "ottai_keya_AABBCCDDEEFF")
            _ = OttaiRegistry.beginGlobalLogin(in: defaults)
            var replies = goodReplies; replies[3] = .init(body: nil, failure: .init(text: "failed", httpStatus: 401))
            XCTAssertThrowsError(try authenticate(replies).get())
            XCTAssertEqual(defaults.string(forKey: "ottai_access_token"), "old-token")
            XCTAssertEqual(defaults.string(forKey: "ottai_keya_AABBCCDDEEFF"), "sensor-keys")
        }
    }

    func testStaleGenerationRegionAndAccountCannotCommit() throws {
        for change in ["generation", "region", "account", "user"] {
            try defaults { defaults in
                let context = try XCTUnwrap(OttaiRegistry.beginGlobalLogin(in: defaults))
                switch change {
                case "generation": _ = OttaiRegistry.beginGlobalLogin(in: defaults)
                case "region": defaults.set(OttaiConstants.apiBaseSyai, forKey: "ottai_api_base")
                case "account": defaults.set("other@example.invalid", forKey: "ottai_account_login")
                default: defaults.set("other-user", forKey: "ottai_user_id")
                }
                XCTAssertFalse(OttaiRegistry.commitGlobalLogin(candidate, email: email, requested: context, in: defaults))
                XCTAssertNil(defaults.string(forKey: "ottai_access_token"))
            }
        }
    }

    func testGlobalOwnerPersistsAcrossReloadAndSessionReset() throws {
        try defaults { defaults in
            let first = OttaiRegistry.loadOrCreateGlobalHeaderDeviceId(in: defaults)
            XCTAssertTrue(OttaiGlobalContract.validDeviceID(first))
            XCTAssertEqual(first, OttaiRegistry.loadOrCreateGlobalHeaderDeviceId(in: defaults))
            OttaiRegistry.clearAccountSession(in: defaults)
            XCTAssertEqual(first, OttaiRegistry.loadOrCreateGlobalHeaderDeviceId(in: defaults))
            XCTAssertFalse(first.contains("ottai-watch"))
        }
    }

    func testProfilesRemainRegionSpecificAndMissingProfileRemainsWatch() throws {
        try defaults { defaults in XCTAssertEqual(OttaiRegistry.loadSessionProfile(in: defaults), .watch) }
        XCTAssertEqual(OttaiCloudClient.activeProfile(OttaiConstants.apiBaseGlobal, stored: .watch), .watch)
        XCTAssertEqual(OttaiCloudClient.activeProfile(OttaiConstants.apiBaseGlobal, stored: .globalPhone), .globalPhone)
        XCTAssertEqual(OttaiCloudClient.activeProfile(OttaiConstants.apiBase, stored: .cnPhone), .cnPhone)
        XCTAssertEqual(OttaiCloudClient.activeProfile(OttaiConstants.apiBase, stored: .globalPhone), .watch)
        XCTAssertEqual(OttaiCloudClient.activeProfile(OttaiConstants.apiBaseSyai, stored: .globalPhone), .watch)
    }

    func testInvalidOwnerStopsBeforeNetwork() {
        let result = OttaiGlobalContract.authenticate(email: email, password: password, deviceID: "bare-uuid", deviceModel: "Fixture", send: { _ in
            XCTFail("Invalid identity must not send requests"); return .init(body: nil, failure: nil)
        })
        XCTAssertThrowsError(try result.get())
    }
}
