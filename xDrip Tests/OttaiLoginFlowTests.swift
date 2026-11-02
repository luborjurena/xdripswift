import XCTest
@testable import xdrip

final class OttaiLoginFlowTests: XCTestCase {
    private typealias Failure = OttaiCloudClient.CloudFailure
    private let web: [String: Any] = ["data": ["accessToken": "synthetic-web-token"]]
    private var mobile: OttaiCloudClient.LoginResult { .init(userId: "42", accessToken: "synthetic-native-token", glucoseSecretKey: "synthetic-root") }

    func testUpgradeUsesServerUsernameAndPersistsOnlyMobileResult() throws {
        var calls: [String] = []
        let result = OttaiLoginFlow.upgrade(webResponse: web, readProfile: { token in
            XCTAssertEqual(token, "synthetic-web-token")
            calls.append("profile")
            return .success(["userName": "server-random-name"])
        }, login: { name, token in
            XCTAssertEqual(name, "server-random-name")
            XCTAssertEqual(token, "")
            calls.append("native-login")
            return .success(self.mobile)
        })
        XCTAssertEqual(try result.get().accessToken, "synthetic-native-token")
        XCTAssertEqual(calls, ["profile", "native-login"])
    }

    func testMobileLoginNeverInheritsWebAuthorization() throws {
        var authorizations: [String] = []
        let result = OttaiLoginFlow.upgrade(webResponse: web, readProfile: { _ in .success(["userName": "server-name"]) }, login: { _, token in
            authorizations.append(token)
            return token.isEmpty ? .success(self.mobile) : .failure(Failure(text: "rejected", code: "AuthFailed_TokenInvalid", httpStatus: 401))
        })
        XCTAssertTrue(try result.get().ok)
        XCTAssertEqual(authorizations, [""])
    }

    func testWrongPasswordIsNeverRetriedOrReplacedWithWebSession() {
        var count = 0
        let result = OttaiLoginFlow.upgrade(webResponse: web, readProfile: { _ in .success(["userName": "server-name"]) }, login: { _, _ in
            count += 1
            return .failure(Failure(text: "password rejected", code: "User_PasswordInvalid"))
        })
        XCTAssertThrowsError(try result.get())
        XCTAssertEqual(count, 1)
    }

    func testTokenInvalidDoesNotRetryPasswordLogin() {
        var count = 0
        let result = OttaiLoginFlow.upgrade(webResponse: web, readProfile: { _ in .success(["userName": "server-name"]) }, login: { _, _ in
            count += 1
            return .failure(Failure(text: "rejected", code: "AuthFailed_TokenInvalid", httpStatus: 401))
        })
        XCTAssertThrowsError(try result.get())
        XCTAssertEqual(count, 1)
    }

    func testProfileRetriesAreBoundedAndMissingUsernameFailsImmediately() {
        var reads = 0
        var sleeps = 0
        let failed = OttaiLoginFlow.upgrade(webResponse: web, readProfile: { _ in
            reads += 1
            return .failure(Failure(text: "temporary profile failure", httpStatus: 503))
        }, login: { _, _ in XCTFail("No username means no login"); return .success(self.mobile) }, retryDelay: { sleeps += 1 })
        XCTAssertThrowsError(try failed.get())
        XCTAssertEqual(reads, 3)
        XCTAssertEqual(sleeps, 2)
        reads = 0
        let missing = OttaiLoginFlow.upgrade(webResponse: web, readProfile: { _ in reads += 1; return .success(["email": "synthetic@example.invalid"]) }, login: { _, _ in XCTFail("Do not guess username from email"); return .success(self.mobile) })
        XCTAssertThrowsError(try missing.get())
        XCTAssertEqual(reads, 1)
    }

    func testIncompleteMobileCredentialsAndWebOnlyReplyCannotSucceed() {
        let incomplete = OttaiLoginFlow.upgrade(webResponse: web, readProfile: { _ in .success(["userName": "name"]) }, login: { _, _ in
            .success(.init(userId: "42", accessToken: "native", glucoseSecretKey: ""))
        })
        XCTAssertThrowsError(try incomplete.get())
        let noToken = OttaiLoginFlow.upgrade(webResponse: ["data": [:]], readProfile: { _ in XCTFail(); return .success([:]) }, login: { _, _ in XCTFail(); return .success(self.mobile) })
        XCTAssertThrowsError(try noToken.get())
    }

    func testNestedJWTAndNumericUserIDAreSupported() {
        let parsed = OttaiLoginFlow.mobileLogin(["userId": 42, "jwtToken": ["accessToken": "synthetic-native"], "glucoseSecretKey": "synthetic-root"])
        XCTAssertEqual(parsed.userId, "42")
        XCTAssertEqual(parsed.accessToken, "synthetic-native")
        XCTAssertTrue(parsed.ok)
        XCTAssertFalse(OttaiLoginFlow.mobileLogin(["accessToken": "null", "glucoseSecretKey": "root"]).ok)
        XCTAssertFalse(OttaiLoginFlow.mobileLogin(["accessToken": "token", "glucoseSecretKey": NSNull()]).ok)
    }

    func test401ClearsOnlyAccountSessionAndKeepsSensorMaterialsRegionAndLoginHint() throws {
        let suite = "OttaiLoginFlowTests." + UUID().uuidString
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        for key in ["ottai_access_token", "ottai_refresh_token", "ottai_glucose_secret_key", "ottai_user_id", "ottai_session_profile"] { defaults.set("synthetic", forKey: key) }
        defaults.set("global-test-region", forKey: "ottai_api_base")
        defaults.set("synthetic@example.invalid", forKey: "ottai_account_login")
        defaults.set("synthetic-ble-material", forKey: "ottai_keya_AABBCCDDEEFF")
        defaults.set(1_790_000_000_000 as Int64, forKey: "ottai_active_time_AABBCCDDEEFF")
        OttaiRegistry.clearAccountSession(in: defaults)
        XCTAssertNil(defaults.string(forKey: "ottai_access_token"))
        XCTAssertNil(defaults.string(forKey: "ottai_refresh_token"))
        XCTAssertNil(defaults.string(forKey: "ottai_glucose_secret_key"))
        XCTAssertNil(defaults.string(forKey: "ottai_user_id"))
        XCTAssertNil(defaults.string(forKey: "ottai_session_profile"))
        XCTAssertEqual(defaults.object(forKey: "ottai_active_time_AABBCCDDEEFF") as? Int64, 1_790_000_000_000)
        XCTAssertEqual(defaults.string(forKey: "ottai_keya_AABBCCDDEEFF"), "synthetic-ble-material")
        XCTAssertEqual(defaults.string(forKey: "ottai_api_base"), "global-test-region")
        XCTAssertEqual(defaults.string(forKey: "ottai_account_login"), "synthetic@example.invalid")
        XCTAssertNotNil(defaults.string(forKey: "ottai_session_generation"))
    }

    func testOnlyAuthenticationFailuresRequestRelogin() {
        XCTAssertTrue(Failure(text: "unauthorized", httpStatus: 401).requiresSignIn)
        XCTAssertTrue(Failure(text: "invalid", code: "AuthFailed_TokenInvalid").requiresSignIn)
        XCTAssertFalse(Failure(text: "forbidden", httpStatus: 403).requiresSignIn)
        XCTAssertFalse(Failure(text: "server", httpStatus: 500).requiresSignIn)
        XCTAssertFalse(Failure(text: "network timeout").requiresSignIn)
        let reply = OttaiCloudClient.decodeRequestResult(status: 401, body: ["code": "AuthFailed_TokenInvalid", "data": ["mac": "AABBCCDDEEFF"]])
        XCTAssertTrue(reply.failure?.requiresSignIn == true)
        XCTAssertEqual(reply.failure?.httpStatus, 401)
    }

    func testAuthFailureInHistoryKeepsReloginReasonAndInvalidatesOldSelectionGeneration() {
        let current = OttaiAccountSensors.Response(body: ["data": ["mac": "AABBCCDDEEFF"]], failure: nil)
        let history = OttaiAccountSensors.Response(body: nil, failure: "unauthorized", requiresSignIn: true)
        XCTAssertThrowsError(try OttaiAccountSensors.snapshot(current: current, history: history)) { error in
            XCTAssertTrue((error as? OttaiAccountSensorsError)?.requiresSignIn == true)
        }
        let first = OttaiAccountContext(apiBase: "global", userId: "42", login: "synthetic", generation: "before")
        let second = OttaiAccountContext(apiBase: "global", userId: "42", login: "synthetic", generation: "after")
        XCTAssertThrowsError(try OttaiAccountSensors.selectedMAC("AABBCCDDEEFF", old: "", requested: first, current: second))
    }
    func testSignInFailuresCarryStageAndDoNotInventUnknownCode() {
        XCTAssertEqual(OttaiCloudClient.requestStage("https://seas.ottai.com/cgm/app/server/user/accountLogin"), "Mobile sign-in")
        XCTAssertEqual(OttaiCloudClient.requestStage("https://www.ottai.com/api/cgm/web/user/getUser"), "Account profile")
        XCTAssertNil(OttaiCloudClient.decodeRequestResult(status: 200, body: ["data": [:]]).failure)
        let failure = OttaiCloudClient.decodeRequestResult(status: 200, body: ["code": "unknown", "message": "Account rejected"]).failure!
        let contextualized = failure.contextualized(stage: "Mobile sign-in", origin: "authenticated")
        XCTAssertEqual(contextualized.code, "unknown")
        XCTAssertTrue(contextualized.displayText.contains("Mobile sign-in [authenticated]"))
        XCTAssertTrue(contextualized.displayText.contains("Account rejected"))
    }

}
