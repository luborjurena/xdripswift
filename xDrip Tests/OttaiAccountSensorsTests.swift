import XCTest
@testable import xdrip

final class OttaiAccountSensorsTests: XCTestCase {
    private let mac = "6CA04230E260"
    private let context = OttaiAccountContext(apiBase: "test", userId: "1", login: "test")
    private func response(_ data: Any) -> OttaiAccountSensors.Response { .init(body: ["code": 200, "data": data], failure: nil) }
    private func history(_ rows: [[String: Any]], key: String = "items") -> OttaiAccountSensors.Response { response([key: rows]) }

    func testCurrentSensorNeedsNoKeyAndOverridesOldHistory() throws {
        let current = response(["cgmDeviceRespVO": ["mac": "6c:a0:42:30:e2:60"], "bindTime": "1790000000000"] as [String: Any])
        let result = try OttaiAccountSensors.snapshot(current: current, history: history([
            ["mac": mac, "unbindTime": 1790000001000], ["mac": "AABBCCDDEEFF", "unbindTime": 0], ["mac": "invalid"]]))
        XCTAssertEqual(result.sensors.map(\.mac), [mac, "AABBCCDDEEFF"])
        XCTAssertTrue(result.sensors[0].boundToAccount)
        XCTAssertNil(result.sensors[0].unboundAt)
        XCTAssertFalse(result.sensors[1].boundToAccount)
        XCTAssertNil(result.sensors[0].activatedAt)
    }

    func testHistoryShapesAndEmptyAccountAreDistinctFromMalformedResponses() throws {
        for key in ["items", "list", "records"] {
            let result = try OttaiAccountSensors.snapshot(current: response(NSNull()), history: history([], key: key))
            XCTAssertTrue(result.sensors.isEmpty)
        }
        XCTAssertTrue(try OttaiAccountSensors.snapshot(current: response([String: Any]()), history: nil).sensors.isEmpty)
        XCTAssertThrowsError(try OttaiAccountSensors.snapshot(current: response(["unexpected": true]), history: history([])))
        XCTAssertThrowsError(try OttaiAccountSensors.snapshot(current: response(NSNull()), history: response(["unexpected": true])))
        XCTAssertThrowsError(try OttaiAccountSensors.snapshot(current: .init(body: [:], failure: nil), history: nil))
    }

    func testSyaiSuccessCodeIsAccepted() throws {
        let current = OttaiAccountSensors.Response(body: ["code": "SUCCESS", "data": ["mac": mac]], failure: nil)
        XCTAssertEqual(try OttaiAccountSensors.snapshot(current: current, history: nil).sensors.first?.mac, mac)
    }

    func testHTTPFailureIsAttachedToItsResponseEvenWhenSharedErrorChanges() {
        let result = OttaiCloudClient.decodeRequestResult(status: 500, body: ["code": 200, "data": ["mac": mac]])
        let previous = OttaiCloudClient.lastFailure
        defer { OttaiCloudClient.lastFailure = previous }
        OttaiCloudClient.lastFailure = nil
        XCTAssertNotNil(result.failure)
        XCTAssertThrowsError(try OttaiAccountSensors.snapshot(current: .init(body: result.body, failure: result.failure?.text), history: nil))
        XCTAssertNil(OttaiCloudClient.decodeRequestResult(status: 200, body: ["code": 200, "data": NSNull()]).failure)
    }

    func testTransportOrBusinessFailureIsNotMaskedByData() {
        let body: [String: Any] = ["code": 403, "data": ["mac": mac]]
        XCTAssertThrowsError(try OttaiAccountSensors.snapshot(current: .init(body: body, failure: nil), history: nil))
        for status in [401, 403] {
            XCTAssertThrowsError(try OttaiAccountSensors.snapshot(current: response(["mac": mac]), history: .init(body: ["data": ["items": []]], failure: "http=\(status)")))
        }
    }

    func testCurrentNeverLostWhenHistoryIsFullAndSyaiUsesCurrentOnly() throws {
        let rows = (0..<80).map { ["mac": String(format: "%012X", $0 + 1)] }
        let result = try OttaiAccountSensors.snapshot(current: response(["mac": mac]), history: history(rows))
        XCTAssertEqual(result.sensors.count, 81)
        XCTAssertEqual(result.sensors.first?.mac, mac)
        XCTAssertTrue(result.note.contains("80"))
        let syai = try OttaiAccountSensors.snapshot(current: response(["mac": mac]), history: nil)
        XCTAssertEqual(syai.sensors.count, 1)
        XCTAssertTrue(syai.note.contains("Syai"))
    }

    func testDatesNormalizeSecondsAndMillisecondsWithoutInventingActivation() {
        XCTAssertEqual(OttaiAccountSensors.date("1790000000"), OttaiAccountSensors.date(1_790_000_000_000 as Int64))
        for value in ["0", "-1", "nan", "infinity", "123"] { XCTAssertNil(OttaiAccountSensors.date(value)) }
    }

    func testDifferentIdentityRequiresManualDisconnect() throws {
        XCTAssertThrowsError(try OttaiAccountSensors.selectedMAC(mac, old: "AABBCCDDEEFF", requested: context, current: context, connectionEnabled: true))
        XCTAssertNil(try OttaiAccountSensors.selectedMAC(mac, old: mac, requested: context, current: context, connectionEnabled: true))
        XCTAssertEqual(try OttaiAccountSensors.selectedMAC(mac, old: "AABBCCDDEEFF", requested: context, current: context, connectionEnabled: false), mac)
    }

    func testSelectionIsLocalIdentityOnlySameSensorIsNoOpAndStaleContextRejected() throws {
        XCTAssertNil(try OttaiAccountSensors.selectedMAC("6c:a0:42:30:e2:60", old: mac, requested: context, current: context))
        XCTAssertEqual(try OttaiAccountSensors.selectedMAC(mac, old: "", requested: context, current: context), mac)
        XCTAssertThrowsError(try OttaiAccountSensors.selectedMAC("bad", old: "", requested: context, current: context))
        let changed = OttaiAccountContext(apiBase: "other", userId: "1", login: "test")
        XCTAssertThrowsError(try OttaiAccountSensors.selectedMAC(mac, old: "", requested: context, current: changed))
        let account = OttaiAccountContext(apiBase: "test", userId: "2", login: "other")
        XCTAssertThrowsError(try OttaiAccountSensors.selectedMAC(mac, old: "", requested: context, current: account))
    }
}
