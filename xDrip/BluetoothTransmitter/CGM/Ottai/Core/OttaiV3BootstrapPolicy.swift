//
//  OttaiV3BootstrapPolicy.swift
//  xdrip
//
//  Ottai / Syai CGM driver — how a connection starts when the sensor has no keyA yet.
//

import Foundation

enum OttaiAuthEntryMode {
    case storedMaterialAuth
    /// Activated through the server; only the bind (which gives keyA) is missing.
    case awaitingBind
    /// New sensor, the user asked to activate it: the server answers the login.
    case serverAssistedActivation
    case blocked
}

/// A sensor without keyA is only touched when the user asked for activation, the V3
/// check marked it (`bootstrapPending`) and the login is still there.
func ottaiAuthEntryMode(
    hasAuthKeys: Bool,
    pendingBind: Bool,
    bootstrapPending: Bool,
    sessionAvailable: Bool,
    activationRequested: Bool
) -> OttaiAuthEntryMode {
    if hasAuthKeys { return .storedMaterialAuth }
    if pendingBind { return .awaitingBind }
    if bootstrapPending, sessionAvailable, activationRequested { return .serverAssistedActivation }
    return .blocked
}

/// Durable intent is distinct from a confirmed activation. An acknowledged GATT write
/// alone must never send an unconfirmed sensor to cloud bind or reset its start time.
struct OttaiActivationAttempt: Codable, Equatable {
    let sensorID: String
    let bluetoothID: String
    let apiBase: String
    let userID: String
    let authorizedAtMs: Int64
    var commandSentAtMs: Int64 = 0
    var commandConnectionID = ""
    var confirmed = false

    func matches(sensorID: String, bluetoothID: String, account: OttaiAccountContext) -> Bool {
        self.sensorID == OttaiConstants.canonicalSensorId(sensorID)
            && self.bluetoothID.caseInsensitiveCompare(bluetoothID) == .orderedSame
            && apiBase == account.apiBase && userID == account.userId
    }

    var isValid: Bool {
        OttaiConstants.looksLikeMac(sensorID) && UUID(uuidString: bluetoothID) != nil
            && !apiBase.isEmpty && !userID.isEmpty && authorizedAtMs > 0
            && commandSentAtMs >= 0 && (!confirmed || commandSentAtMs > 0)
            && (commandSentAtMs == 0 || UUID(uuidString: commandConnectionID) != nil)
    }
}

enum OttaiActivationGate: Equatable {
    case readStatus
    case writeFrames
    case confirmOnly
    /// A different authenticated BLE connection freshly read cmd 0...2. The old
    /// connection cannot deliver its command now, so the authorized attempt may resume.
    case retryConfirmedInactive
    case bind(startMs: Int64)
    case alreadyActive
    case ended

    static func decide(commandStatus: Int, commandSentAtMs: Int64, commandFromCurrentConnection: Bool = true) -> Self {
        if commandStatus < 0 { return .readStatus }
        if commandStatus >= 4 { return .ended }
        if commandStatus == 3 {
            return commandSentAtMs > 0 ? .bind(startMs: commandSentAtMs) : .alreadyActive
        }
        // A command may have landed even without its callback. Read back, do not
        // repeat coefficient/RTC/duration writes during this uncertain state.
        if commandSentAtMs > 0 { return commandFromCurrentConnection ? .confirmOnly : .retryConfirmedInactive }
        return .writeFrames
    }
}

/// Shared by the real GATT writer and its interruption tests.
enum OttaiServerActivationWrite: Int, CaseIterable {
    case coefficient, duration, rtc, activate

    var characteristic: String {
        switch self {
        case .coefficient: return OttaiConstants.charDestructive
        case .duration: return OttaiConstants.charMaxActiveTime
        case .rtc: return OttaiConstants.charCurrentTime
        case .activate: return OttaiConstants.charCommand
        }
    }

    var next: Self? { Self(rawValue: rawValue + 1) }
}

/// Provisioning frames from the Global M8 SDK 1.38.0. Kept separate from the
/// older CN/Syai activation sequence: its retain-time write is not a Global step.
enum OttaiGlobalActivation {
    static let defaultActiveExpireMs: Int64 = 14 * 24 * 3600 * 1000
    enum Failure: String, Error, LocalizedError {
        case firmware = "This Global firmware has no verified activation protocol in this build."
        case coefficients = "The new sensor's factory coefficients are missing or invalid. Fetch them again before activation."
        case calibration = "This sensor requires factory calibration K/B. The cloud did not provide them. No activation was attempted."
        case duration = "The sensor lifetime is missing or invalid."
        case encryption = "The Bluetooth session key is not available for activation."
        var errorDescription: String? { rawValue }
    }

    enum Kind: Equatable { case coefficients, calibration, duration, rtc, activate }
    struct Write: Equatable {
        let kind: Kind
        let characteristic: String
        let bytes: [UInt8]
    }

    static func firmwareMinor(_ version: String) -> Int? {
        guard let regex = try? NSRegularExpression(pattern: #"V1\.([0-9]+)\."#) else { return nil }
        let matches = regex.matches(in: version, range: NSRange(version.startIndex..., in: version))
        guard matches.count == 1, let range = Range(matches[0].range(at: 1), in: version),
              ["6", "7", "8"].contains(String(version[range])), let minor = Int(version[range]) else { return nil }
        return minor
    }

    /// The Global bind API expects the live SDK software version, including its
    /// E...(V1...) wrapper. Only the comma suffix is removed by the official reader.
    static func bindFirmware(_ raw: String) -> String? {
        let version = String(raw.split(separator: ",", omittingEmptySubsequences: false).first ?? "")
            .trimmingCharacters(in: .controlCharacters.union(.whitespaces))
        return firmwareMinor(version) == nil ? nil : version
    }

    static func preflight(materials: OttaiRegistry.DeviceMaterials) throws {
        guard let minor = firmwareMinor(materials.deviceVersion) else { throw Failure.firmware }
        guard materials.coefficient.split(separator: ",", omittingEmptySubsequences: false).count == materials.coefficients.count else { throw Failure.coefficients }
        _ = try coefficientFrame(materials.coefficients)
        if minor == 8 {
            guard let k = materials.calibrationValueK, let b = materials.calibrationValueB,
                  k.isFinite, b.isFinite else { throw Failure.calibration }
        }
        _ = try totalDurationMs(materials)
    }

    static func coefficientFrame(_ coefficients: [Double]) throws -> [UInt8] {
        guard (1...255).contains(coefficients.count), coefficients.allSatisfy({ $0.isFinite && Float($0).isFinite }) else { throw Failure.coefficients }
        var bytes: [UInt8] = [0x09, UInt8(coefficients.count)]
        for value in coefficients {
            let bits = Float(value).bitPattern
            bytes += (0..<4).map { UInt8(truncatingIfNeeded: bits >> ($0 * 8)) }
        }
        var crc: UInt16 = 0xffff
        for byte in bytes {
            crc ^= UInt16(byte)
            for _ in 0..<8 { crc = crc & 1 == 1 ? (crc >> 1) ^ 0xa001 : crc >> 1 }
        }
        return bytes + [UInt8(truncatingIfNeeded: crc), UInt8(truncatingIfNeeded: crc >> 8)]
    }

    static func writes(materials: OttaiRegistry.DeviceMaterials, sessionKeyHex: String) throws -> [Write] {
        try preflight(materials: materials)
        guard let minor = firmwareMinor(materials.deviceVersion) else { throw Failure.firmware }
        var result = [Write(kind: .coefficients, characteristic: OttaiConstants.charDestructive,
                            bytes: try coefficientFrame(materials.coefficients))]
        if minor == 8 {
            guard let k = materials.calibrationValueK, let b = materials.calibrationValueB,
                  k.isFinite, b.isFinite else { throw Failure.calibration }
            let plain = [k, b].flatMap { value in (0..<8).map { UInt8(truncatingIfNeeded: value.bitPattern >> ($0 * 8)) } }
            guard let cipher = OttaiCrypto.encryptPayload(plain, sessionKeyHex: sessionKeyHex) else { throw Failure.encryption }
            result.append(Write(kind: .calibration, characteristic: OttaiConstants.charDestructive, bytes: [0x0b] + cipher))
        }
        let duration = try totalDurationMs(materials)
        let seconds = duration / 1000
        guard seconds > 0, seconds <= Int64(UInt32.max), duration % 1000 == 0 else { throw Failure.duration }
        let durationBytes = (0..<4).map { UInt8(truncatingIfNeeded: UInt32(seconds) >> ($0 * 8)) }
        guard let encryptedDuration = OttaiCrypto.encryptPayload(durationBytes, sessionKeyHex: sessionKeyHex),
              let activate = OttaiCrypto.encryptActivateCmd([0x03], sessionKeyHex: sessionKeyHex) else { throw Failure.encryption }
        result += [Write(kind: .duration, characteristic: OttaiConstants.charMaxActiveTime, bytes: encryptedDuration),
                   Write(kind: .rtc, characteristic: OttaiConstants.charCurrentTime, bytes: [0, 0, 0, 0]),
                   Write(kind: .activate, characteristic: OttaiConstants.charCommand, bytes: activate)]
        return result
    }

    static func totalDurationMs(_ materials: OttaiRegistry.DeviceMaterials) throws -> Int64 {
        // Missing Global metadata is defaulted when authInfo is decoded (14d/0/0).
        // Explicit invalid/zero expiry must never silently become the CN 15d default.
        guard materials.activeExpireTimeMs > 0 else { throw Failure.duration }
        let parts = [materials.activeExpireTimeMs, materials.preheatPeriodMs, materials.gracePeriodMs]
        var total: Int64 = 0
        for part in parts {
            guard part >= 0 else { throw Failure.duration }
            let sum = total.addingReportingOverflow(part)
            guard !sum.overflow else { throw Failure.duration }
            total = sum.partialValue
        }
        guard total > 0, total % 1000 == 0, total / 1000 <= Int64(UInt32.max) else { throw Failure.duration }
        return total
    }
}
