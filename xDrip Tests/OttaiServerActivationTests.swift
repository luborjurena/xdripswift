//
//  OttaiServerActivationTests.swift
//  xdripTests
//
//  Server-assisted activation of new Syai sensors.
//

import XCTest
@testable import xdrip

final class OttaiServerActivationTests: XCTestCase {

    // MARK: - entry mode

    private func mode(keys: Bool = false, pendingBind: Bool = false, bootstrap: Bool = true,
                      session: Bool = true, requested: Bool = true) -> OttaiAuthEntryMode {
        ottaiAuthEntryMode(hasAuthKeys: keys, pendingBind: pendingBind, bootstrapPending: bootstrap,
                           sessionAvailable: session, activationRequested: requested)
    }

    func testStoredKeysAlwaysWin() {
        XCTAssertEqual(mode(keys: true, pendingBind: true), .storedMaterialAuth)
    }

    func testPendingBindNeverActivatesAgain() {
        XCTAssertEqual(mode(pendingBind: true), .awaitingBind)
    }

    func testServerActivationNeedsTheUsersRequest() {
        XCTAssertEqual(mode(requested: false), .blocked)
        XCTAssertEqual(mode(), .serverAssistedActivation)
    }

    func testServerActivationNeedsAV3CheckAndASession() {
        XCTAssertEqual(mode(bootstrap: false), .blocked)
        XCTAssertEqual(mode(session: false), .blocked)
    }

    // MARK: - validateDeviceByMacV3 (China; Syai always uses V3)

    func testChinaMovesOnToV3OnlyOnUpgradeCode() {
        XCTAssertTrue(OttaiCloudClient.shouldTryValidateV3(apiBase: OttaiConstants.apiBase, profile: .cnPhone, v2FailureCode: "AppDevice_Upgrade_Version"))
        XCTAssertFalse(OttaiCloudClient.shouldTryValidateV3(apiBase: OttaiConstants.apiBase, profile: .cnPhone, v2FailureCode: "AppDevice_AlreadyUsed"))
        XCTAssertFalse(OttaiCloudClient.shouldTryValidateV3(apiBase: OttaiConstants.apiBase, profile: .watch, v2FailureCode: "AppDevice_Upgrade_Version"))
        XCTAssertFalse(OttaiCloudClient.shouldTryValidateV3(apiBase: OttaiConstants.apiBaseGlobal, profile: .watch, v2FailureCode: "AppDevice_Upgrade_Version"))
    }

    func testChinaBindV3Body() {
        let body = OttaiCloudClient.bindRequestBody(mac: "6CA04230E260", deviceVersion: "v", userId: "42", activeTime: 1_760_000_000, contract: .v3)
        XCTAssertEqual(body["newBindType"] as? Int, 2)
        XCTAssertEqual(body["userId"] as? String, "42")
    }

    // MARK: - Syai client

    func testUnbindTypeFollowsWearTime() {
        var m = OttaiRegistry.DeviceMaterials()
        m.activeTimeMs = 1_000_000
        m.activeExpireTimeMs = 15 * 86_400_000
        XCTAssertEqual(OttaiCloudClient.syaiUnbindType(materials: m, acceptedMaxActiveMs: 0, nowMs: 1_000_000 + 16 * 86_400_000), 10)
        XCTAssertEqual(OttaiCloudClient.syaiUnbindType(materials: m, acceptedMaxActiveMs: 0, nowMs: 1_000_000 + 86_400_000), 13)
    }

    func testTraceIdIsVersion1() {
        let id = OttaiSyaiClient.traceId()
        let parts = id.split(separator: "-")
        XCTAssertEqual(parts.map(\.count), [8, 4, 4, 4, 12])
        XCTAssertEqual(parts[2].first, "1")
    }

    func testJwtPayload() {
        // {"sub":"42","app_name":"Syai Tag"}
        let jwt = "x.eyJzdWIiOiI0MiIsImFwcF9uYW1lIjoiU3lhaSBUYWcifQ.y"
        XCTAssertEqual(OttaiSyaiClient.jwtPayload(jwt)?["sub"] as? String, "42")
        XCTAssertEqual(OttaiSyaiClient.jwtPayload(jwt)?["app_name"] as? String, "Syai Tag")
    }

    func testUploadAddsCheckpointEveryFifthReading() {
        func sample(_ n: Int) -> OttaiCloudUploader.Sample {
            OttaiCloudUploader.Sample(dataNo: n, runtimeSec: n * 60, voltage: 1, rawCurrent: 2, temperatureC: 30, mmol: 5.5,
                                      sampleMs: 0, receivedAtMs: 0, originBytes: [1, 2], live: true)
        }
        var m = OttaiRegistry.DeviceMaterials()
        m.deviceId = 7
        let list = OttaiCloudUploader.uploadBody(batch: [sample(4), sample(5)], materials: m)["dataList"] as? [[String: Any]]
        XCTAssertEqual(list?.map { $0["dataType"] as? Int }, [1, 1, 2])
        XCTAssertTrue(list?[2]["origin"] is NSNull)
    }

    // MARK: - firmware -> deviceVersion

    func testDeviceVersionFromFirmware() {
        XCTAssertEqual(OttaiCloudClient.deviceVersion(fromFirmware: "E2.0.3(V1.7.SH22601.3),STDRD"), "V1.7.SH22601.3")
        XCTAssertEqual(OttaiCloudClient.deviceVersion(fromFirmware: " V1.7.S2530.1 "), "V1.7.S2530.1")
        XCTAssertEqual(OttaiCloudClient.deviceVersion(fromFirmware: "E1.1()"), "E1.1()")
    }

    // MARK: - Activation readback and interruption recovery

    private let activationSensor = "AABBCCDDEEFF"
    private let activationBluetoothID = "7D473D30-41C1-45D0-A3C5-E91F41187211"
    private let activationConnectionID = "BF30A437-9665-4FA3-921E-E95AB7ECBA48"
    private let activationStart: Int64 = 1_790_000_000_000

    private var activationAccount: OttaiAccountContext {
        OttaiAccountContext(apiBase: OttaiConstants.apiBaseGlobal, userId: "fixture-user", login: "fixture@example.invalid", generation: "session-one")
    }

    private func activationAttempt(sent: Bool = false, confirmed: Bool = false) -> OttaiActivationAttempt {
        var attempt = OttaiActivationAttempt(sensorID: activationSensor, bluetoothID: activationBluetoothID,
            apiBase: activationAccount.apiBase, userID: activationAccount.userId, authorizedAtMs: activationStart - 5_000)
        if sent {
            attempt.commandSentAtMs = activationStart
            attempt.commandConnectionID = activationConnectionID
        }
        attempt.confirmed = confirmed
        return attempt
    }

    private func withActivationDefaults(_ body: (UserDefaults) throws -> Void) rethrows {
        let suite = "OttaiActivationTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        try body(defaults)
    }

    func testActivationCannotBeginBeforeReadingCommandStatus() {
        XCTAssertEqual(OttaiActivationGate.decide(commandStatus: -1, commandSentAtMs: 0), .readStatus)
        XCTAssertEqual(OttaiActivationGate.decide(commandStatus: -1, commandSentAtMs: activationStart,
            commandFromCurrentConnection: false), .readStatus)
    }

    func testOnlyAnUnstartedSensorWithoutASentCommandMayWriteFrames() {
        for status in 0...2 {
            XCTAssertEqual(OttaiActivationGate.decide(commandStatus: status, commandSentAtMs: 0), .writeFrames)
        }
        XCTAssertEqual(OttaiActivationGate.decide(commandStatus: 3, commandSentAtMs: 0), .alreadyActive)
        XCTAssertEqual(OttaiActivationGate.decide(commandStatus: 4, commandSentAtMs: 0), .ended)
    }

    func testUncertainCommandOnTheSameConnectionNeverRewritesActivationFrames() {
        for status in 0...2 {
            XCTAssertEqual(OttaiActivationGate.decide(commandStatus: status, commandSentAtMs: activationStart), .confirmOnly)
        }
        XCTAssertEqual(OttaiActivationGate.decide(commandStatus: 3, commandSentAtMs: activationStart), .bind(startMs: activationStart))
    }

    func testAnotherAuthenticatedConnectionCanRetryOnlyAfterAFreshInactiveReadback() {
        for status in 0...2 {
            XCTAssertEqual(OttaiActivationGate.decide(commandStatus: status, commandSentAtMs: activationStart,
                commandFromCurrentConnection: false), .retryConfirmedInactive)
        }
        XCTAssertEqual(OttaiActivationGate.decide(commandStatus: 3, commandSentAtMs: activationStart,
            commandFromCurrentConnection: false), .bind(startMs: activationStart))
    }

    func testEndedSensorNeverBindsOrReactivatesAfterAnInterruptedWrite() {
        for status in [4, 5, 255] {
            for sameConnection in [false, true] {
                XCTAssertEqual(OttaiActivationGate.decide(commandStatus: status, commandSentAtMs: activationStart,
                    commandFromCurrentConnection: sameConnection), .ended)
            }
        }
    }

    func testActivationWriteAcknowledgmentIsInsufficientForBinding() {
        // A sent command with the old inactive status remains uncertain. Only the
        // sensor's active readback can authorize cloud bind.
        XCTAssertEqual(OttaiActivationGate.decide(commandStatus: 0, commandSentAtMs: activationStart), .confirmOnly)
        XCTAssertEqual(OttaiActivationGate.decide(commandStatus: 3, commandSentAtMs: activationStart), .bind(startMs: activationStart))
    }

    func testServerWriteOrderStopsAfterTheActivationCommand() {
        var step: OttaiServerActivationWrite? = .coefficient
        var sequence: [OttaiServerActivationWrite] = []
        while let current = step {
            sequence.append(current)
            step = current.next
            XCTAssertLessThanOrEqual(sequence.count, 4)
            if sequence.count > 4 { break }
        }
        XCTAssertEqual(sequence, [.coefficient, .duration, .rtc, .activate])
        XCTAssertNil(OttaiServerActivationWrite.activate.next)
        XCTAssertEqual(sequence.map(\.characteristic), [OttaiConstants.charDestructive, OttaiConstants.charMaxActiveTime,
            OttaiConstants.charCurrentTime, OttaiConstants.charCommand])
        XCTAssertEqual(Set(sequence.map(\.characteristic)).count, 4)
    }

    func testInterruptionBeforeAndAfterTheCommandHasDifferentRecovery() throws {
        try withActivationDefaults { defaults in
            for lastWrite in OttaiServerActivationWrite.allCases {
                let attempt = activationAttempt(sent: lastWrite == .activate)
                XCTAssertTrue(OttaiRegistry.saveActivationCheckpoint(attempt, in: defaults))
                let restored = try XCTUnwrap(OttaiRegistry.loadActivationCheckpoint(activationSensor, in: defaults))
                if lastWrite == .activate {
                    XCTAssertEqual(OttaiActivationGate.decide(commandStatus: 0, commandSentAtMs: restored.commandSentAtMs), .confirmOnly)
                    XCTAssertEqual(OttaiActivationGate.decide(commandStatus: 3, commandSentAtMs: restored.commandSentAtMs), .bind(startMs: activationStart))
                } else {
                    XCTAssertEqual(OttaiActivationGate.decide(commandStatus: 0, commandSentAtMs: restored.commandSentAtMs), .writeFrames)
                    XCTAssertEqual(OttaiActivationGate.decide(commandStatus: 3, commandSentAtMs: restored.commandSentAtMs), .alreadyActive)
                }
            }
        }
    }

    // MARK: - Durable identity and account scope

    func testCheckpointRoundTripPreservesTheOriginalCommandTime() throws {
        try withActivationDefaults { defaults in
            let attempt = activationAttempt(sent: true)
            XCTAssertTrue(OttaiRegistry.saveActivationCheckpoint(attempt, in: defaults))
            let restored = try XCTUnwrap(OttaiRegistry.loadActivationCheckpoint(activationSensor, in: defaults))
            XCTAssertEqual(restored, attempt)
            XCTAssertEqual(restored.commandSentAtMs, activationStart)
            XCTAssertEqual(restored.commandConnectionID, activationConnectionID)
            XCTAssertFalse(restored.confirmed)
        }
    }

    func testConfirmedCheckpointRetainsTimeAndDoesNotAuthorizeActivationAgain() throws {
        try withActivationDefaults { defaults in
            let attempt = activationAttempt(sent: true, confirmed: true)
            XCTAssertTrue(OttaiRegistry.saveActivationCheckpoint(attempt, in: defaults))
            XCTAssertEqual(OttaiRegistry.loadActivationCheckpoint(activationSensor, in: defaults), attempt)
            XCTAssertEqual(mode(pendingBind: true, requested: true), .awaitingBind)
        }
    }

    func testCheckpointMatchesCanonicalMACAndCaseInsensitiveBluetoothUUID() {
        let attempt = activationAttempt(sent: true)
        XCTAssertTrue(attempt.matches(sensorID: "aa:bb:cc:dd:ee:ff", bluetoothID: activationBluetoothID.lowercased(), account: activationAccount))
        XCTAssertFalse(attempt.matches(sensorID: "001122334455", bluetoothID: activationBluetoothID, account: activationAccount))
        XCTAssertFalse(attempt.matches(sensorID: activationSensor, bluetoothID: "D0CD9FBE-66D5-4C26-9044-933E4442CA15", account: activationAccount))
    }

    func testCheckpointCannotCrossUserOrRegion() {
        let attempt = activationAttempt(sent: true)
        let otherUser = OttaiAccountContext(apiBase: activationAccount.apiBase, userId: "other-user", login: activationAccount.login)
        let otherRegion = OttaiAccountContext(apiBase: OttaiConstants.apiBase, userId: activationAccount.userId, login: activationAccount.login)
        XCTAssertFalse(attempt.matches(sensorID: activationSensor, bluetoothID: activationBluetoothID, account: otherUser))
        XCTAssertFalse(attempt.matches(sensorID: activationSensor, bluetoothID: activationBluetoothID, account: otherRegion))
    }

    func testReauthenticationRejectsStaleCallbackButKeepsTheSameUsersRecoveryIntent() {
        withActivationDefaults { defaults in
            defaults.set(activationAccount.apiBase, forKey: "ottai_api_base")
            defaults.set(activationAccount.userId, forKey: "ottai_user_id")
            defaults.set(activationAccount.login, forKey: "ottai_account_login")
            defaults.set(activationAccount.generation, forKey: "ottai_session_generation")
            XCTAssertTrue(OttaiRegistry.isCurrent(activationAccount, in: defaults))
            defaults.set("session-two", forKey: "ottai_session_generation")
            XCTAssertFalse(OttaiRegistry.isCurrent(activationAccount, in: defaults))
            let current = OttaiRegistry.accountContext(in: defaults)
            XCTAssertTrue(activationAttempt(sent: true).matches(sensorID: activationSensor,
                bluetoothID: activationBluetoothID, account: current))
        }
    }

    func testInvalidCheckpointIsNotPersisted() {
        withActivationDefaults { defaults in
            let invalid = [
                OttaiActivationAttempt(sensorID: "not-a-mac", bluetoothID: activationBluetoothID, apiBase: activationAccount.apiBase, userID: activationAccount.userId, authorizedAtMs: activationStart),
                OttaiActivationAttempt(sensorID: activationSensor, bluetoothID: "not-a-uuid", apiBase: activationAccount.apiBase, userID: activationAccount.userId, authorizedAtMs: activationStart),
                OttaiActivationAttempt(sensorID: activationSensor, bluetoothID: activationBluetoothID, apiBase: "", userID: activationAccount.userId, authorizedAtMs: activationStart),
                OttaiActivationAttempt(sensorID: activationSensor, bluetoothID: activationBluetoothID, apiBase: activationAccount.apiBase, userID: "", authorizedAtMs: activationStart),
                OttaiActivationAttempt(sensorID: activationSensor, bluetoothID: activationBluetoothID, apiBase: activationAccount.apiBase, userID: activationAccount.userId, authorizedAtMs: 0)
            ]
            for attempt in invalid {
                XCTAssertFalse(OttaiRegistry.saveActivationCheckpoint(attempt, in: defaults))
            }
            var negativeWrite = activationAttempt()
            negativeWrite.commandSentAtMs = -1
            XCTAssertFalse(OttaiRegistry.saveActivationCheckpoint(negativeWrite, in: defaults))
            XCTAssertFalse(OttaiRegistry.saveActivationCheckpoint(activationAttempt(confirmed: true), in: defaults))
            XCTAssertNil(OttaiRegistry.loadActivationCheckpoint(activationSensor, in: defaults))
        }
    }

    func testCorruptOrWrongSensorCheckpointCannotBeRestored() throws {
        try withActivationDefaults { defaults in
            let key = "ottai_activation_checkpoint_\(activationSensor)"
            defaults.set(Data("{corrupted".utf8), forKey: key)
            XCTAssertNil(OttaiRegistry.loadActivationCheckpoint(activationSensor, in: defaults))
            var wrongSensor = activationAttempt(sent: true)
            let encoded = try JSONEncoder().encode(wrongSensor)
            defaults.set(encoded, forKey: "ottai_activation_checkpoint_001122334455")
            XCTAssertNil(OttaiRegistry.loadActivationCheckpoint("001122334455", in: defaults))
            wrongSensor.confirmed = true
            defaults.set(try JSONEncoder().encode(wrongSensor), forKey: key)
            XCTAssertEqual(OttaiRegistry.loadActivationCheckpoint(activationSensor, in: defaults), wrongSensor)
        }
    }

    func testClearingOneCheckpointDoesNotDeleteAnotherSensorsRecovery() throws {
        try withActivationDefaults { defaults in
            let first = activationAttempt(sent: true)
            let second = OttaiActivationAttempt(sensorID: "001122334455", bluetoothID: activationBluetoothID,
                apiBase: activationAccount.apiBase, userID: activationAccount.userId, authorizedAtMs: activationStart)
            XCTAssertTrue(OttaiRegistry.saveActivationCheckpoint(first, in: defaults))
            XCTAssertTrue(OttaiRegistry.saveActivationCheckpoint(second, in: defaults))
            OttaiRegistry.clearActivationCheckpoint(activationSensor, in: defaults)
            XCTAssertNil(OttaiRegistry.loadActivationCheckpoint(activationSensor, in: defaults))
            XCTAssertEqual(try XCTUnwrap(OttaiRegistry.loadActivationCheckpoint(second.sensorID, in: defaults)), second)
        }
    }

    // MARK: - Warmup and required calculation materials

    func testWarmupSuppressesTenMinuteAndLastPreHourSamples() {
        XCTAssertEqual(OttaiConstants.defaultWarmupSeconds, 3600)
        XCTAssertTrue(OttaiConstants.isWithinWarmup(activationStartMs: activationStart, sampleMs: activationStart + 600_000))
        XCTAssertTrue(OttaiConstants.isWithinWarmup(activationStartMs: activationStart, sampleMs: activationStart + 3_599_999))
        XCTAssertFalse(OttaiConstants.isWithinWarmup(activationStartMs: activationStart, sampleMs: activationStart + 3_600_000))
    }

    func testCloudWarmupCannotShortenTheManufacturerHourButMayExtendIt() {
        XCTAssertTrue(OttaiConstants.isWithinWarmup(activationStartMs: activationStart,
            sampleMs: activationStart + 3_000_000, preheatPeriodMs: 600_000))
        XCTAssertTrue(OttaiConstants.isWithinWarmup(activationStartMs: activationStart,
            sampleMs: activationStart + 3_600_000, preheatPeriodMs: 5_400_000))
        XCTAssertFalse(OttaiConstants.isWithinWarmup(activationStartMs: activationStart,
            sampleMs: activationStart + 5_400_000, preheatPeriodMs: 5_400_000))
    }

    private func validCalculationMaterials() -> OttaiRegistry.DeviceMaterials {
        OttaiRegistry.DeviceMaterials(keyAHex: String(repeating: "AB", count: 96), method: "V1 C0 ml",
            coefficient: "1.0,2.0,3.0", activeTimeMs: 0)
    }

    func testUnstartedSensorCanHaveCompleteMaterialsWithoutInventingActivationTime() {
        let materials = validCalculationMaterials()
        XCTAssertTrue(OttaiCloudClient.materialsAreComplete(materials))
        XCTAssertEqual(materials.activeTimeMs, 0)
    }

    func testActivationRequiresValidAuthKeysAndAFormula() {
        var materials = validCalculationMaterials()
        materials.keyAHex = ""
        XCTAssertFalse(OttaiCloudClient.materialsAreComplete(materials))
        materials = validCalculationMaterials()
        materials.keyAHex = String(repeating: "G", count: 192)
        XCTAssertFalse(OttaiCloudClient.materialsAreComplete(materials))
        materials = validCalculationMaterials()
        materials.method = " \n "
        XCTAssertFalse(OttaiCloudClient.materialsAreComplete(materials))
    }

    func testMalformedNonFiniteOrMissingCoefficientsBlockActivation() {
        for coefficient in ["", "1,,2", "1,banana,2", "1,2,", "1,NaN,2", "1,inf,2"] {
            var materials = validCalculationMaterials()
            materials.coefficient = coefficient
            XCTAssertFalse(OttaiCloudClient.materialsAreComplete(materials), "Invalid coefficients must not prepare activation: \(coefficient)")
        }
    }

    func testFormulaCannotReferenceACoefficientMissingFromTheSensorMaterials() {
        var materials = validCalculationMaterials()
        materials.method = "V1 C13 ml"
        XCTAssertFalse(OttaiCloudClient.materialsAreComplete(materials))
    }

    func testNativeGlobalNeverGuessesChinaV3ValidationOnUpgradeFailure() {
        XCTAssertFalse(OttaiCloudClient.shouldTryValidateV3(apiBase: OttaiConstants.apiBaseGlobal,
            profile: .globalPhone, v2FailureCode: OttaiCloudClient.bizUpgradeVersion))
    }

    func testSentCheckpointRequiresTheOriginalBluetoothConnectionIdentity() {
        withActivationDefaults { defaults in
            var missingConnection = activationAttempt(sent: true)
            missingConnection.commandConnectionID = ""
            XCTAssertFalse(OttaiRegistry.saveActivationCheckpoint(missingConnection, in: defaults))
            missingConnection.commandConnectionID = "not-a-connection-uuid"
            XCTAssertFalse(OttaiRegistry.saveActivationCheckpoint(missingConnection, in: defaults))
            XCTAssertNil(OttaiRegistry.loadActivationCheckpoint(activationSensor, in: defaults))
        }
    }

    // MARK: - Official Global M8 read-only authInfo and legacy bind contracts

    private let globalOwner = "ottai-seas:a:g:ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
    private let globalTimestamp: Int64 = 1_790_000_000_123

    func testGlobalAuthInfoRequestUsesReadOnlyM8ContractAndTheSameHeaderTimestamp() throws {
        let request = try XCTUnwrap(OttaiGlobalContract.authInfoRequest(mac: "aa:bb:cc:dd:ee:ff",
            deviceID: globalOwner, accessToken: "fixture-access-token", timestamp: globalTimestamp, deviceModel: "FixturePhone"))
        XCTAssertEqual(request.method, "GET")
        XCTAssertEqual(request.url, "https://seas.ottai.com/cgm/app/server/device/authInfo")
        XCTAssertEqual(Set(request.query.keys), ["mac", "sign"])
        XCTAssertEqual(request.query["mac"], activationSensor)
        XCTAssertEqual(request.query["sign"], "ca49777236c23a9ad3bdc491a8e50d0d")
        XCTAssertNil(request.query["signature"])
        XCTAssertNil(request.body)
        XCTAssertEqual(request.headers["appName"], "ottai-seas")
        XCTAssertEqual(request.headers["packageName"], "com.ottai.seas")
        XCTAssertEqual(request.headers["applicationType"], "ottai_seas")
        XCTAssertEqual(request.headers["deviceId"], globalOwner)
        XCTAssertEqual(request.headers["timestamp"], String(globalTimestamp))
        XCTAssertEqual(request.headers["productModel"], "M8")
        XCTAssertEqual(request.headers["Authorization"], "fixture-access-token")
    }

    func testGlobalAuthInfoSignerMatchesAnIndependentDigestAndCanonicalMAC() {
        // Independent Python hashlib/OpenSSL-compatible MD5 fixture for the published SDK seed.
        XCTAssertEqual(OttaiCloudClient.globalAuthInfoSign(deviceID: globalOwner, timestampMillis: globalTimestamp,
            mac: activationSensor), "ca49777236c23a9ad3bdc491a8e50d0d")
        XCTAssertEqual(OttaiCloudClient.globalAuthInfoSign(deviceID: globalOwner, timestampMillis: globalTimestamp,
            mac: activationSensor.lowercased()), "ca49777236c23a9ad3bdc491a8e50d0d")
    }

    func testInvalidIdentityOrMissingSessionCannotCreateAnAuthInfoRequest() {
        XCTAssertNil(OttaiGlobalContract.authInfoRequest(mac: "not-a-mac", deviceID: globalOwner,
            accessToken: "fixture-token", timestamp: globalTimestamp, deviceModel: "FixturePhone"))
        XCTAssertNil(OttaiGlobalContract.authInfoRequest(mac: activationSensor, deviceID: "bare-device-id",
            accessToken: "fixture-token", timestamp: globalTimestamp, deviceModel: "FixturePhone"))
        XCTAssertNil(OttaiGlobalContract.authInfoRequest(mac: activationSensor, deviceID: globalOwner,
            accessToken: "", timestamp: globalTimestamp, deviceModel: "FixturePhone"))
    }

    private func globalValidationFixture() -> [String: Any] {
        ["data": [
            "cgmDeviceRespVO": ["mac": activationSensor, "keyA": "", "produceTime": 123,
                                "deviceVersion": "fixture-version", "activeTime": 0],
            "cgmDeviceMethodVO": ["method": "V1 C0 ml", "coefficient": "1.0,2.0,3.0",
                                  "methodUpdateTime": 456, "coeffUpdateTime": 789]
        ]]
    }

    func testAuthInfoMergePreservesV2CalculationDataAndUpdatesOnlyAuthMetadata() throws {
        let validation = globalValidationFixture()
        let auth: [String: Any] = ["data": ["mac": activationSensor, "keyA": "fixture-encrypted-key",
            "produceTime": 321, "preheatPeriodTime": 3_600_000,
            "method": "must-not-replace-method", "coefficient": "must-not-replace-coefficients"]]
        let merged = try XCTUnwrap(OttaiGlobalContract.mergeAuthInfo(validation: validation, authInfo: auth, mac: activationSensor))
        let data = try XCTUnwrap(merged["data"] as? [String: Any])
        let device = try XCTUnwrap(data["cgmDeviceRespVO"] as? [String: Any])
        let method = try XCTUnwrap(data["cgmDeviceMethodVO"] as? [String: Any])
        XCTAssertEqual(device["keyA"] as? String, "fixture-encrypted-key")
        XCTAssertEqual(device["produceTime"] as? Int, 321)
        XCTAssertEqual(device["preheatPeriodTime"] as? Int, 3_600_000)
        XCTAssertEqual(device["deviceVersion"] as? String, "fixture-version")
        XCTAssertEqual(device["activeTime"] as? Int, 0)
        XCTAssertEqual(method["method"] as? String, "V1 C0 ml")
        XCTAssertEqual(method["coefficient"] as? String, "1.0,2.0,3.0")
        XCTAssertEqual(method["methodUpdateTime"] as? Int, 456)
        XCTAssertEqual(method["coeffUpdateTime"] as? Int, 789)
        let originalData = try XCTUnwrap(validation["data"] as? [String: Any])
        XCTAssertEqual((originalData["cgmDeviceRespVO"] as? [String: Any])?["keyA"] as? String, "")
    }

    func testAuthInfoCannotMergeAnotherSensorOrAnEmptyKeyIntoTheNewSensor() {
        let validation = globalValidationFixture()
        for authData: [String: Any] in [
            ["mac": "001122334455", "keyA": "fixture-encrypted-key"],
            ["keyA": "fixture-encrypted-key"],
            ["mac": activationSensor, "keyA": ""],
            ["mac": activationSensor, "keyA": NSNull()],
            ["mac": activationSensor]
        ] {
            XCTAssertNil(OttaiGlobalContract.mergeAuthInfo(validation: validation,
                authInfo: ["data": authData], mac: activationSensor))
        }
        XCTAssertNil(OttaiGlobalContract.mergeAuthInfo(validation: validation,
            authInfo: ["data": ["mac": activationSensor, "keyA": "fixture-encrypted-key"]], mac: "001122334455"))
    }

    func testGlobalM8BindKeepsMillisecondsAndUsesItsOwnNewBindType() {
        let body = OttaiCloudClient.bindRequestBody(mac: activationSensor, deviceVersion: "fixture-version",
            userId: "fixture-user", activeTime: globalTimestamp, contract: .globalM8)
        XCTAssertEqual(body["newBindType"] as? Int, 1)
        XCTAssertEqual(body["activeTime"] as? Int64, globalTimestamp)
        XCTAssertEqual(body["deviceType"] as? String, "cgm")
        XCTAssertEqual(body["mac"] as? String, activationSensor)
        XCTAssertEqual(body["deviceVersion"] as? String, "fixture-version")
        XCTAssertEqual(body["userId"] as? String, "fixture-user")
    }

    // MARK: - Global M8 activation wire fixtures

    private let activationSessionKey = "000102030405060708090A0B0C0D0E0F"

    private func globalActivationMaterials(minor: Int = 7) -> OttaiRegistry.DeviceMaterials {
        var materials = validCalculationMaterials()
        materials.deviceVersion = "E1.2.7(V1.\(minor).SH2640.3)"
        materials.coefficient = (1...14).map(String.init).joined(separator: ",")
        materials.activeExpireTimeMs = 14 * 86_400_000
        materials.preheatPeriodMs = 3_600_000
        materials.gracePeriodMs = 14_400_000
        materials.calibrationValueK = 1.25
        materials.calibrationValueB = -2.5
        return materials
    }

    func testGlobalCoefficientFrameMatchesIndependentFloat32AndModbusCRCFixture() throws {
        let frame = try OttaiGlobalActivation.coefficientFrame((1...14).map(Double.init))
        // Python struct '<14f' + independent Modbus CRC fixture; no encryption.
        let expected = try OttaiCrypto.hexToBytesStrict("090e0000803f0000004000004040000080400000a0400000c0400000e0400000004100001041000020410000304100004041000050410000604185cb")
        XCTAssertEqual(frame, expected)
        XCTAssertEqual(frame.count, 60)
        XCTAssertEqual(Array(frame.suffix(2)), [0x85, 0xcb])
    }

    func testGlobalCoefficientFrameSupportsItsOneByteCountBoundaries() throws {
        let single = try OttaiGlobalActivation.coefficientFrame([1.0])
        XCTAssertEqual(Array(single.prefix(6)), [0x09, 0x01, 0x00, 0x00, 0x80, 0x3f])
        XCTAssertEqual(single.count, 8)
        let largest = try OttaiGlobalActivation.coefficientFrame([Double](repeating: 1.0, count: 255))
        XCTAssertEqual(Array(largest.prefix(2)), [0x09, 0xff])
        XCTAssertEqual(largest.count, 1_024)
        for values in [[Double](), [Double](repeating: 1.0, count: 256)] {
            XCTAssertThrowsError(try OttaiGlobalActivation.coefficientFrame(values)) {
                XCTAssertEqual($0 as? OttaiGlobalActivation.Failure, .coefficients)
            }
        }
    }

    func testGlobalCoefficientFrameRejectsNonFiniteAndFloat32OverflowValues() {
        for value in [Double.nan, Double.infinity, -Double.infinity, Double.greatestFiniteMagnitude] {
            XCTAssertThrowsError(try OttaiGlobalActivation.coefficientFrame([value])) {
                XCTAssertEqual($0 as? OttaiGlobalActivation.Failure, .coefficients)
            }
        }
    }

    func testGlobalFirmwareAllowsOneVerifiedMinorInVendorVersionWrappers() {
        for minor in 6...8 {
            XCTAssertEqual(OttaiGlobalActivation.firmwareMinor("V1.\(minor).SH2640.3"), minor)
            XCTAssertEqual(OttaiGlobalActivation.firmwareMinor("M8 E1.2.7(V1.\(minor).SH2640.3),STDRD"), minor)
        }
    }

    func testGlobalFirmwareRejectsUnknownAmbiguousOrNonCanonicalVersions() {
        for firmware in ["", "M8", "1.7.SH2640.3", "v1.7.SH2640.3", "V1.5.SH2500.1", "V1.9.SH2700.1",
                         "V1.07.SH2640.3", "V1.7", "V1.7.SH2640.3 V1.8.SH2700.1", "V1.7.SH2640.3 V1.7.SH2640.3"] {
            XCTAssertNil(OttaiGlobalActivation.firmwareMinor(firmware), firmware)
        }
    }

    func testGlobalSixAndSevenWriteCoefficientDurationZeroRTCThenActivation() throws {
        for minor in [6, 7] {
            let writes = try OttaiGlobalActivation.writes(materials: globalActivationMaterials(minor: minor), sessionKeyHex: activationSessionKey)
            XCTAssertEqual(writes.map(\.kind), [.coefficients, .duration, .rtc, .activate])
            XCTAssertEqual(writes.map(\.characteristic), [OttaiConstants.charDestructive, OttaiConstants.charMaxActiveTime,
                OttaiConstants.charCurrentTime, OttaiConstants.charCommand])
            XCTAssertEqual(writes[0].bytes.first, 0x09)
            XCTAssertEqual(writes[2].bytes, [0, 0, 0, 0])
        }
    }

    func testGlobalEightInsertsFactoryCalibrationBeforeDuration() throws {
        let writes = try OttaiGlobalActivation.writes(materials: globalActivationMaterials(minor: 8), sessionKeyHex: activationSessionKey)
        XCTAssertEqual(writes.map(\.kind), [.coefficients, .calibration, .duration, .rtc, .activate])
        XCTAssertEqual(writes[1].characteristic, OttaiConstants.charDestructive)
        XCTAssertEqual(writes[1].bytes.count, 17)
        XCTAssertEqual(writes[1].bytes.first, 0x0b)
        // OpenSSL AES-128-ECB fixture for Float64LE(1.25) || Float64LE(-2.5).
        XCTAssertEqual(Array(writes[1].bytes.dropFirst()), try OttaiCrypto.hexToBytesStrict("a516df6f00d956e999fe568cd86b08bc"))
        let decoded = try XCTUnwrap(OttaiCrypto.decryptPayload(Array(writes[1].bytes.dropFirst()), sessionKeyHex: activationSessionKey))
        XCTAssertEqual(decoded, try OttaiCrypto.hexToBytesStrict("000000000000f43f00000000000004c0"))
    }

    func testGlobalDurationIncludesLifetimeWarmupAndGraceAndMatchesAESFixture() throws {
        let materials = globalActivationMaterials()
        XCTAssertEqual(try OttaiGlobalActivation.totalDurationMs(materials), 1_227_600_000)
        let writes = try OttaiGlobalActivation.writes(materials: materials, sessionKeyHex: activationSessionKey)
        let duration = try XCTUnwrap(writes.first { $0.kind == .duration })
        XCTAssertEqual(duration.bytes, try OttaiCrypto.hexToBytesStrict("8608f92cc7d690795ca608415d9e469c"))
        let decoded = try XCTUnwrap(OttaiCrypto.decryptPayload(duration.bytes, sessionKeyHex: activationSessionKey))
        XCTAssertEqual(Array(decoded.prefix(4)), [0x50, 0xbb, 0x12, 0x00])
        XCTAssertTrue(decoded.dropFirst(4).allSatisfy { $0 == 0 })
    }

    func testGlobalActivationUsesZeroPadded03AESAndIgnoresLegacyRetainTime() throws {
        var materials = globalActivationMaterials()
        let first = try OttaiGlobalActivation.writes(materials: materials, sessionKeyHex: activationSessionKey)
        materials.retainTimeMs = Int64.max
        let withUnrelatedRetainTime = try OttaiGlobalActivation.writes(materials: materials, sessionKeyHex: activationSessionKey)
        XCTAssertEqual(first, withUnrelatedRetainTime)
        let activate = try XCTUnwrap(first.last)
        XCTAssertEqual(activate.kind, .activate)
        XCTAssertEqual(activate.bytes, try OttaiCrypto.hexToBytesStrict("8cb899148f1fa8ff9132d0eb15a936f2"))
        let decoded = try XCTUnwrap(OttaiCrypto.decryptPayload(activate.bytes, sessionKeyHex: activationSessionKey))
        XCTAssertEqual(decoded.first, 0x03)
        XCTAssertTrue(decoded.dropFirst().allSatisfy { $0 == 0 })
    }

    func testGlobalEightRequiresBothFiniteFactoryCalibrationValues() {
        var cases: [OttaiRegistry.DeviceMaterials] = []
        var noK = globalActivationMaterials(minor: 8); noK.calibrationValueK = nil; cases.append(noK)
        var noB = globalActivationMaterials(minor: 8); noB.calibrationValueB = nil; cases.append(noB)
        var invalidK = globalActivationMaterials(minor: 8); invalidK.calibrationValueK = .nan; cases.append(invalidK)
        var invalidB = globalActivationMaterials(minor: 8); invalidB.calibrationValueB = .infinity; cases.append(invalidB)
        for materials in cases {
            XCTAssertThrowsError(try OttaiGlobalActivation.writes(materials: materials, sessionKeyHex: activationSessionKey)) {
                XCTAssertEqual($0 as? OttaiGlobalActivation.Failure, .calibration)
            }
        }
    }

    func testGlobalOlderVerifiedFirmwareDoesNotRequireUnusedCalibrationValues() throws {
        var materials = globalActivationMaterials(minor: 7)
        materials.calibrationValueK = nil
        materials.calibrationValueB = nil
        XCTAssertEqual(try OttaiGlobalActivation.writes(materials: materials, sessionKeyHex: activationSessionKey).map(\.kind),
            [.coefficients, .duration, .rtc, .activate])
    }

    func testGlobalPlanRejectsInvalidSessionKeysWithoutProducingWrites() {
        for key in ["", "not-hex", "AB"] {
            XCTAssertThrowsError(try OttaiGlobalActivation.writes(materials: globalActivationMaterials(), sessionKeyHex: key)) {
                XCTAssertEqual($0 as? OttaiGlobalActivation.Failure, .encryption)
            }
        }
    }

    func testGlobalDurationRejectsNegativeGraceFractionalSecondsAndOverflows() {
        var cases: [OttaiRegistry.DeviceMaterials] = []
        var negativeGrace = globalActivationMaterials(); negativeGrace.gracePeriodMs = -1; cases.append(negativeGrace)
        var fractional = globalActivationMaterials(); fractional.activeExpireTimeMs += 1; cases.append(fractional)
        var sumOverflow = globalActivationMaterials(); sumOverflow.activeExpireTimeMs = Int64.max; cases.append(sumOverflow)
        var wireOverflow = globalActivationMaterials(); wireOverflow.activeExpireTimeMs = (Int64(UInt32.max) + 1) * 1000; cases.append(wireOverflow)
        for materials in cases {
            XCTAssertThrowsError(try OttaiGlobalActivation.totalDurationMs(materials)) {
                XCTAssertEqual($0 as? OttaiGlobalActivation.Failure, .duration)
            }
        }
    }

    func testGlobalPlanStopsBeforeWritesForUnknownFirmware() {
        var materials = globalActivationMaterials()
        materials.deviceVersion = "unrecognized-new-revision"
        XCTAssertThrowsError(try OttaiGlobalActivation.writes(materials: materials, sessionKeyHex: activationSessionKey)) {
            XCTAssertEqual($0 as? OttaiGlobalActivation.Failure, .firmware)
        }
    }

    // MARK: - Production read-only sensor preparation flow

    func testGlobalCheckedSensorPerformsTwoGETsAndNeverBindsOrActivates() throws {
        var requests: [OttaiGlobalContract.Request] = []
        var nextTimestamp = globalTimestamp
        let result = OttaiGlobalContract.checkedSensor(mac: activationSensor, deviceID: globalOwner,
            accessToken: "fixture-access-token", deviceModel: "FixturePhone", send: { request in
                requests.append(request)
                switch requests.count {
                case 1: return .init(body: self.globalValidationFixture(), failure: nil)
                case 2: return .init(body: ["data": ["mac": self.activationSensor, "keyA": "fixture-key", "produceTime": 321]], failure: nil)
                default: XCTFail("A read-only check must not issue extra requests"); return .init(body: nil, failure: .init(text: "unexpected request"))
                }
            }, clock: { defer { nextTimestamp += 1 }; return nextTimestamp })
        _ = try result.get()
        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(requests.map(\.method), ["GET", "GET"])
        XCTAssertEqual(requests.map(\.url), ["https://seas.ottai.com/cgm/app/server/device/validateDeviceByMacV2",
            "https://seas.ottai.com/cgm/app/server/device/authInfo"])
        XCTAssertTrue(requests.allSatisfy { $0.body == nil })
        XCTAssertEqual(Set(requests[0].query.keys), ["mac", "signature"])
        XCTAssertEqual(Set(requests[1].query.keys), ["mac", "sign"])
        XCTAssertEqual(requests[0].headers["timestamp"], String(globalTimestamp))
        XCTAssertEqual(requests[1].headers["timestamp"], String(globalTimestamp + 1))
        XCTAssertTrue(requests.allSatisfy { $0.headers["Authorization"] == "fixture-access-token" })
        XCTAssertTrue(requests.allSatisfy { $0.headers["productModel"] == "M8" })
    }

    func testGlobalCheckedSensorStopsAtAValidationFailureWithoutRequestingKeys() {
        var requests: [OttaiGlobalContract.Request] = []
        let result = OttaiGlobalContract.checkedSensor(mac: activationSensor, deviceID: globalOwner,
            accessToken: "fixture-token", deviceModel: "FixturePhone", send: { request in
                requests.append(request)
                return .init(body: self.globalValidationFixture(), failure: .init(text: "fixture refusal", code: "AppDevice_Upgrade_Version", httpStatus: 200))
            })
        XCTAssertThrowsError(try result.get())
        XCTAssertEqual(requests.count, 1)
        XCTAssertEqual(requests.first?.method, "GET")
    }

    func testGlobalCheckedSensorDoesNotTryMutationFallbackAfterAuthInfoFailure() {
        var requests: [OttaiGlobalContract.Request] = []
        let result = OttaiGlobalContract.checkedSensor(mac: activationSensor, deviceID: globalOwner,
            accessToken: "fixture-token", deviceModel: "FixturePhone", send: { request in
                requests.append(request)
                return requests.count == 1
                    ? .init(body: self.globalValidationFixture(), failure: nil)
                    : .init(body: nil, failure: .init(text: "fixture expired session", code: "AuthFailed_TokenInvalid", httpStatus: 401))
            })
        XCTAssertThrowsError(try result.get())
        XCTAssertEqual(requests.count, 2)
        XCTAssertTrue(requests.allSatisfy { $0.method == "GET" && $0.body == nil })
    }

    func testGlobalCheckedSensorRejectsCrossSensorAuthReplyWithoutAnyFollowupRequest() {
        var count = 0
        let result = OttaiGlobalContract.checkedSensor(mac: activationSensor, deviceID: globalOwner,
            accessToken: "fixture-token", deviceModel: "FixturePhone", send: { _ in
                count += 1
                return count == 1
                    ? .init(body: self.globalValidationFixture(), failure: nil)
                    : .init(body: ["data": ["mac": "001122334455", "keyA": "fixture-key"]], failure: nil)
            })
        XCTAssertThrowsError(try result.get())
        XCTAssertEqual(count, 2)
    }

    // MARK: - Global metadata defaults and cache preparation regressions

    func testGlobalDurationNeverSubstitutesChinaDefaultsForInvalidExplicitMetadata() {
        var missingExpiry = globalActivationMaterials(); missingExpiry.activeExpireTimeMs = 0
        var negativeExpiry = globalActivationMaterials(); negativeExpiry.activeExpireTimeMs = -1
        var negativePreheat = globalActivationMaterials(); negativePreheat.preheatPeriodMs = -1
        for materials in [missingExpiry, negativeExpiry, negativePreheat] {
            XCTAssertThrowsError(try OttaiGlobalActivation.totalDurationMs(materials)) {
                XCTAssertEqual($0 as? OttaiGlobalActivation.Failure, .duration)
            }
        }
    }

    func testGlobalZeroPreheatAndGraceRemainZeroInDurationInsteadOfAddingAnHour() throws {
        var materials = globalActivationMaterials()
        materials.preheatPeriodMs = 0
        materials.gracePeriodMs = 0
        XCTAssertEqual(try OttaiGlobalActivation.totalDurationMs(materials), 14 * 86_400_000)
    }

    func testAuthInfoMissingLifetimeMetadataUsesOfficialGlobalFourteenDayDefaults() throws {
        var validation = globalValidationFixture()
        var validationData = try XCTUnwrap(validation["data"] as? [String: Any])
        var validationVO = try XCTUnwrap(validationData["cgmDeviceRespVO"] as? [String: Any])
        validationVO["activeExpireTime"] = Int64(15 * 86_400_000)
        validationVO["preheatPeriodTime"] = Int64(3_600_000)
        validationVO["gracePeriodTime"] = Int64(14_400_000)
        validationData["cgmDeviceRespVO"] = validationVO
        validation["data"] = validationData
        let auth: [String: Any] = ["data": ["mac": activationSensor, "keyA": "fixture-key", "produceTime": 321]]
        let merged = try XCTUnwrap(OttaiGlobalContract.mergeAuthInfo(validation: validation, authInfo: auth, mac: activationSensor))
        let data = try XCTUnwrap(merged["data"] as? [String: Any])
        let device = try XCTUnwrap(data["cgmDeviceRespVO"] as? [String: Any])
        XCTAssertEqual((device["activeExpireTime"] as? NSNumber)?.int64Value, 14 * 86_400_000)
        XCTAssertEqual((device["preheatPeriodTime"] as? NSNumber)?.int64Value, 0)
        XCTAssertEqual((device["gracePeriodTime"] as? NSNumber)?.int64Value, 0)
    }

    func testAuthInfoExplicitZeroExpiryIsPreservedAndRejectedByTheActivationPlan() throws {
        let auth: [String: Any] = ["data": ["mac": activationSensor, "keyA": "fixture-key", "produceTime": 321,
            "activeExpireTime": 0, "preheatPeriodTime": 0, "gracePeriodTime": 0]]
        let merged = try XCTUnwrap(OttaiGlobalContract.mergeAuthInfo(validation: globalValidationFixture(), authInfo: auth, mac: activationSensor))
        let data = try XCTUnwrap(merged["data"] as? [String: Any])
        let device = try XCTUnwrap(data["cgmDeviceRespVO"] as? [String: Any])
        XCTAssertEqual((device["activeExpireTime"] as? NSNumber)?.int64Value, 0)
        var materials = globalActivationMaterials()
        materials.activeExpireTimeMs = try XCTUnwrap((device["activeExpireTime"] as? NSNumber)?.int64Value)
        XCTAssertThrowsError(try OttaiGlobalActivation.writes(materials: materials, sessionKeyHex: activationSessionKey)) {
            XCTAssertEqual($0 as? OttaiGlobalActivation.Failure, .duration)
        }
    }

    func testIncompleteNewGlobalEightCacheDoesNotPreventFetchingFactoryCalibrationAgain() {
        var materials = globalActivationMaterials(minor: 8)
        materials.calibrationValueK = nil
        materials.calibrationValueB = nil
        XCTAssertTrue(OttaiCloudClient.materialsAreComplete(materials))
        XCTAssertFalse(OttaiCloudClient.materialsReadyForSetup(materials,
            apiBase: OttaiConstants.apiBaseGlobal, profile: .globalPhone))
        materials.calibrationValueK = 1.25
        materials.calibrationValueB = -2.5
        XCTAssertTrue(OttaiCloudClient.materialsReadyForSetup(materials,
            apiBase: OttaiConstants.apiBaseGlobal, profile: .globalPhone))
    }

    func testRunningGlobalSensorAndOtherProfilesDoNotNeedNewSensorActivationPreflight() {
        var materials = validCalculationMaterials()
        materials.deviceVersion = "unknown-firmware"
        XCTAssertFalse(OttaiCloudClient.materialsReadyForSetup(materials,
            apiBase: OttaiConstants.apiBaseGlobal, profile: .globalPhone))
        XCTAssertTrue(OttaiCloudClient.materialsReadyForSetup(materials,
            apiBase: OttaiConstants.apiBaseGlobal, profile: .watch))
        XCTAssertTrue(OttaiCloudClient.materialsReadyForSetup(materials,
            apiBase: OttaiConstants.apiBase, profile: .cnPhone))
        materials.activeTimeMs = activationStart
        XCTAssertTrue(OttaiCloudClient.materialsReadyForSetup(materials,
            apiBase: OttaiConstants.apiBaseGlobal, profile: .globalPhone))
    }

    func testGlobalPreflightIndependentlyRejectsMalformedCloudCoefficientCSV() {
        for csv in ["1,,2", "1,bad,2", "1,2,", ",1,2"] {
            var materials = globalActivationMaterials()
            materials.coefficient = csv
            XCTAssertThrowsError(try OttaiGlobalActivation.preflight(materials: materials)) {
                XCTAssertEqual($0 as? OttaiGlobalActivation.Failure, .coefficients)
            }
        }
    }

    func testGlobalBindFirmwareKeepsTheFullLiveVersionWrapper() {
        XCTAssertEqual(OttaiGlobalActivation.bindFirmware("E1.2.7(V1.7.SH2640.3),STDRD"), "E1.2.7(V1.7.SH2640.3)")
        XCTAssertEqual(OttaiGlobalActivation.bindFirmware("E2.0.3(V1.8.SH2700.1),STDRD"), "E2.0.3(V1.8.SH2700.1)")
        XCTAssertNotEqual(OttaiGlobalActivation.bindFirmware("E1.2.7(V1.7.SH2640.3),STDRD"), "V1.7.SH2640.3")
    }

    func testGlobalBindFirmwareRemovesOnlySurroundingControlWhitespaceAndSuffix() {
        XCTAssertEqual(OttaiGlobalActivation.bindFirmware("\u{0000}\n\t E1.2.7(V1.6.SH2500.1) \r\t,STDRD\n"),
            "E1.2.7(V1.6.SH2500.1)")
        XCTAssertEqual(OttaiGlobalActivation.bindFirmware(" V1.7.SH2640.3 \t"), "V1.7.SH2640.3")
    }

    func testGlobalBindFirmwareRejectsUnknownOrAmbiguousFirstVersionField() {
        for raw in ["", " ,STDRD", "E1.2.7(unknown),STDRD", "E1.2.7(V1.9.SH2700.1),STDRD",
                    "E1.2.7(V1.7.SH2640.3 V1.8.SH2700.1),STDRD", ",E1.2.7(V1.7.SH2640.3)"] {
            XCTAssertNil(OttaiGlobalActivation.bindFirmware(raw), raw)
        }
    }
}
