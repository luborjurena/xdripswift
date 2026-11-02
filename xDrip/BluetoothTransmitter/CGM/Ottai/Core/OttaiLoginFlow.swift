import Foundation

/// Converts a web session into the device-scoped session required by Ottai's mobile API.
/// Contract: JugglucoNG 11e6e29, OttaiCloudClient.kt upgradeWebSession. Never persist the web JWT.
enum OttaiLoginFlow {
    typealias Failure = OttaiCloudClient.CloudFailure
    typealias Login = OttaiCloudClient.LoginResult

    private static func string(_ value: Any?) -> String {
        let text = (value as? String) ?? (value as? NSNumber)?.stringValue ?? ""
        return text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || text == "null" ? "" : text
    }

    static func accessToken(_ data: [String: Any]) -> String {
        let tokens = data["jwtToken"] as? [String: Any] ?? data
        return string(tokens["accessToken"])
    }

    static func mobileLogin(_ data: [String: Any]) -> Login {
        Login(userId: string(data["userId"]), accessToken: accessToken(data), glucoseSecretKey: string(data["glucoseSecretKey"]))
    }

    static func upgrade(webResponse: [String: Any],
                        readProfile: (String) -> Result<[String: Any], Failure>,
                        login: (String, String) -> Result<Login, Failure>,
                        retryDelay: () -> Void = {}) -> Result<Login, Failure> {
        let data = webResponse["data"] as? [String: Any] ?? webResponse["result"] as? [String: Any] ?? [:]
        let webToken = accessToken(data)
        guard !webToken.isEmpty else { return .failure(Failure(text: "Web login returned no session.")) }
        var name: String?
        var profileFailure = Failure(text: "Account profile lookup failed.")
        for attempt in 0..<3 {
            switch readProfile(webToken) {
            case .success(let profile):
                let userName = string(profile["userName"])
                guard !userName.isEmpty else {
                    return .failure(Failure(text: "Account profile has no username; a mobile session could not be created."))
                }
                name = userName
            case .failure(let failure): profileFailure = failure
            }
            if name != nil { break }
            if attempt < 2 { retryDelay() }
        }
        guard let name else { return .failure(profileFailure) }
        // Global password sign-in is unauthenticated: the web JWT is only for getUser.
        // This is the original Global header shape documented by JugglucoNG. One password
        // attempt only; do not retry unknown errors or replay a web-scoped token here.
        return login(name, "").flatMap { session in
            session.ok ? .success(session) : .failure(Failure(text: "Mobile login returned incomplete credentials."))
        }
    }
}
