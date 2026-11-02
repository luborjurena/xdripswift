import Foundation

/// The encrypted gateway must not redirect signed credentials to a different route or host.
enum OttaiSecureHTTP {
    final class NoRedirect: NSObject, URLSessionTaskDelegate {
        func urlSession(_ session: URLSession, task: URLSessionTask,
                        willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                        completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    }

    static func send(_ method: String, url: String, body: String?, headers: [String: String], timeoutMs: Int = 30_000) throws -> OttaiNetSecurity.Reply {
        guard let target = URL(string: url), target.scheme == "https", target.host == "seas.ottai.com",
              target.port == nil, target.path.hasPrefix("/cgm/security/app/server/") else {
            throw OttaiSecureTransportFailure(diagnostic: "secure_http_target")
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        let session = URLSession(configuration: configuration, delegate: NoRedirect(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: target)
        request.httpMethod = method
        request.timeoutInterval = TimeInterval(timeoutMs) / 1000
        request.httpBody = body.map { Data($0.utf8) }
        for (key, value) in headers { request.setValue(value, forHTTPHeaderField: key) }
        let gate = DispatchSemaphore(value: 0)
        var data: Data?, response: HTTPURLResponse?, failed = false
        let task = session.dataTask(with: request) { received, http, error in
            data = received; response = http as? HTTPURLResponse; failed = error != nil
            gate.signal()
        }
        task.resume()
        guard gate.wait(timeout: .now() + .milliseconds(timeoutMs + 5_000)) == .success else {
            throw OttaiSecureTransportFailure(diagnostic: "secure_http_timeout")
        }
        guard !failed, let response else { throw OttaiSecureTransportFailure(diagnostic: "secure_http_network") }
        let json = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        return .init(status: response.statusCode, json: json)
    }
}
