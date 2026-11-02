import Foundation

/// A read-only account snapshot. Account linkage does not establish sensor health or lifetime.
struct OttaiAccountSensor: Equatable {
    let mac: String
    let serialNumber: String
    let firmware: String
    let boundToAccount: Bool
    let boundAt: Date?
    let unboundAt: Date?
    let activatedAt: Date?

    var title: String {
        var parts = [mac, boundToAccount ? "Currently linked to account" : "Account history — not currently linked"]
        if !serialNumber.isEmpty { parts.append("Serial: " + serialNumber) }
        if !firmware.isEmpty { parts.append("Firmware: " + firmware) }
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        if let boundAt { parts.append("Linked: " + formatter.string(from: boundAt)) }
        if let unboundAt { parts.append("Unlinked: " + formatter.string(from: unboundAt)) }
        if let activatedAt { parts.append("Cloud activation: " + formatter.string(from: activatedAt)) }
        parts.append("Sensor activity: not checked over Bluetooth")
        return parts.joined(separator: "\n")
    }
}

struct OttaiAccountContext: Equatable {
    let apiBase: String
    let userId: String
    let login: String
    var generation: String = ""
}

struct OttaiAccountSensorsSnapshot {
    let sensors: [OttaiAccountSensor]
    let note: String
}

struct OttaiAccountSensorsError: LocalizedError {
    let message: String
    var requiresSignIn: Bool = false
    var errorDescription: String? { message }
}

enum OttaiAccountSensors {
    /// Failures are captured immediately alongside their response, never read later on the UI queue.
    struct Response {
        let body: [String: Any]?
        let failure: String?
        var requiresSignIn: Bool = false
    }

    static func canonicalMAC(_ value: String) -> String? {
        let mac = value.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: ":", with: "").replacingOccurrences(of: "-", with: "").uppercased()
        guard mac.count == 12, mac.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) }) else { return nil }
        return mac
    }

    /// Only local identity changes are represented here; no cloud mutation or connection effect exists.
    static func selectedMAC(_ proposed: String, old: String, requested: OttaiAccountContext, current: OttaiAccountContext, connectionEnabled: Bool = false) throws -> String? {
        guard requested == current else { throw OttaiAccountSensorsError(message: "Account or region changed. Load the sensor list again.") }
        guard let mac = canonicalMAC(proposed) else { throw OttaiAccountSensorsError(message: "The selected sensor has no valid MAC.") }
        if mac == canonicalMAC(old) { return nil }
        guard !connectionEnabled else { throw OttaiAccountSensorsError(message: "Tap Stop Scanning, then confirm Disconnect before choosing a different sensor. The cloud binding will stay unchanged.") }
        return mac
    }

    static func snapshot(current: Response, history: Response?) throws -> OttaiAccountSensorsSnapshot {
        let currentBody = try checked(current)
        let currentObject = try payload(currentBody)
        let currentSensor: OttaiAccountSensor?
        if currentObject == nil || currentObject?.isEmpty == true {
            currentSensor = nil
        } else {
            guard let object = currentObject, let sensor = parseSensor(object, bound: true) else {
                throw OttaiAccountSensorsError(message: "The account binding response has no valid sensor MAC.")
            }
            currentSensor = sensor
        }
        var sensors = currentSensor.map { [$0] } ?? []
        var note = "Choosing a sensor only saves its ID on this phone. It does not activate, bind, unbind or connect a sensor. Use Fetch sensor from cloud separately."
        if let history {
            // Any failed history lookup is an error, even if it included data; never hide an expired session.
            let body = try checked(history)
            guard let data = try payload(body), let rows = (data["items"] ?? data["list"] ?? data["records"]) as? [[String: Any]] else {
                throw OttaiAccountSensorsError(message: "The sensor history response has an unsupported format.")
            }
            var seen = Set(sensors.map(\.mac))
            for row in rows {
                if let sensor = parseSensor(row, bound: false), seen.insert(sensor.mac).inserted { sensors.append(sensor) }
            }
            note += " The current account binding and up to 80 history records are shown. Account linkage is not proof that a sensor is running."
        } else {
            note += " Syai: only the current account binding is available; history is not requested."
        }
        return OttaiAccountSensorsSnapshot(sensors: sensors, note: note)
    }

    private static func checked(_ response: Response) throws -> [String: Any] {
        if let failure = response.failure { throw OttaiAccountSensorsError(message: failure, requiresSignIn: response.requiresSignIn) }
        guard let body = response.body else { throw OttaiAccountSensorsError(message: "Empty cloud response.") }
        let code = string(body["code"])
        guard code.isEmpty || code == "200" || code.uppercased() == "OK" || code.uppercased() == "SUCCESS" else {
            throw OttaiAccountSensorsError(message: "Cloud request failed (code \(code)).")
        }
        return body
    }

    private static func payload(_ body: [String: Any]) throws -> [String: Any]? {
        guard let value = body["data"] ?? body["result"] else { throw OttaiAccountSensorsError(message: "Cloud response is missing its data field.") }
        if value is NSNull { return nil }
        guard let object = value as? [String: Any] else { throw OttaiAccountSensorsError(message: "Cloud response has an unsupported data format.") }
        return object
    }

    private static func parseSensor(_ object: [String: Any], bound: Bool) -> OttaiAccountSensor? {
        let device = object["cgmDeviceRespVO"] as? [String: Any] ?? object
        guard let mac = canonicalMAC(string(device["mac"] ?? object["mac"])) else { return nil }
        return OttaiAccountSensor(mac: mac, serialNumber: string(device["serialNo"] ?? object["serialNo"]),
            firmware: string(device["deviceVersion"] ?? object["deviceVersion"]), boundToAccount: bound,
            boundAt: date(object["bindTime"] ?? device["bindTime"]),
            unboundAt: bound ? nil : date(object["unbindTime"] ?? device["unbindTime"]),
            activatedAt: date(device["activeTime"] ?? object["activeTime"]))
    }

    static func date(_ value: Any?) -> Date? {
        guard let raw = Double(string(value)), raw.isFinite, raw >= 1_000_000_000 else { return nil }
        let seconds = raw >= 1_000_000_000_000 ? raw / 1000 : raw
        guard seconds < 32_503_680_000 else { return nil }
        return Date(timeIntervalSince1970: seconds)
    }

    private static func string(_ value: Any?) -> String {
        if let value = value as? String { return value }
        return (value as? NSNumber)?.stringValue ?? ""
    }
}
