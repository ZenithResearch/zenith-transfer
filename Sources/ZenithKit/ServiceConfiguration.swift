import Foundation

/// Public proposed configuration bundled by the distributor. Loading it never
/// installs trust; the person still reviews and approves it inside Wallet.
public struct MembershipConfiguration: Codable, Sendable {
  public let name: String
  public let endpoint: URL
  public let scope: String?
  public let trust: TrustConfiguration
  public struct TrustConfiguration: Codable, Sendable {
    public let v3: V3?
    public let v4: V4?
    public struct Root: Codable, Sendable {
      public let issuerId: String
      public let keyId: String
      public let signatureSuite: String
      public let publicKey: String
    }
    public struct V3: Codable, Sendable {
      public let schema: String
      public let version: Int
      public let roots: [Root]
    }
    public struct Genesis: Codable, Sendable {
      public let schema: String
      public let version: Int
      public let scopeType: String
      public let alias: String
      public let nonce: String
    }
    public struct Scope: Codable, Sendable {
      public let scopeId: String
      public let genesis: Genesis
      public let issuerIds: [String]
    }
    public struct V4: Codable, Sendable {
      public let schema: String
      public let version: Int
      public let roots: [Root]
      public let scopes: [Scope]
    }
  }
  public func validate() throws {
    guard !name.isEmpty, name.count <= 80, endpoint.scheme == "https", endpoint.host != nil,
      endpoint.user == nil, endpoint.password == nil, endpoint.query == nil,
      endpoint.fragment == nil,
      scope == nil ? trust.v3 != nil : trust.v4 != nil
    else { throw WalletFailure.core("service_setup_required") }
    let roots = (trust.v3?.roots ?? []) + (trust.v4?.roots ?? [])
    guard !roots.isEmpty, roots.count <= 32,
      roots.allSatisfy({ !$0.issuerId.isEmpty && $0.issuerId.count <= 256 &&
        !$0.keyId.isEmpty && $0.keyId.count <= 256 && $0.signatureSuite == "Ed25519" &&
        $0.publicKey.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil }),
      scope == nil || scope?.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    else { throw WalletFailure.core("service_setup_required") }
  }
  public var trustData: Data { get throws { try JSONEncoder().encode(trust) } }
}

/// Ephemeral, cookie-free transport. A redirect never forwards an approved
/// request or a credential to a different destination, including same-origin paths.
private final class RedirectBlocker: NSObject, URLSessionTaskDelegate {
  let lanTrust: LANServerTrust?
  init(lanTrust: LANServerTrust?) { self.lanTrust = lanTrust }
  func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    urlSession(session, didReceive: challenge, completionHandler: completionHandler)
  }
  func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    guard let lanTrust else { completionHandler(.performDefaultHandling, nil); return }
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
      challenge.previousFailureCount == 0,
      let trust = challenge.protectionSpace.serverTrust,
      lanTrust.accepts(trust, host: challenge.protectionSpace.host, port: challenge.protectionSpace.port)
    else { completionHandler(.cancelAuthenticationChallenge, nil); return }
    completionHandler(.useCredential, URLCredential(trust: trust))
  }
  func urlSession(
    _ session: URLSession, task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
    completionHandler: @escaping (URLRequest?) -> Void
  ) { completionHandler(nil) }
}
public final class PrivateTransport: @unchecked Sendable {
  private let configurationProvider: @Sendable () async throws -> URLSessionConfiguration
  private let lanTrust: LANServerTrust?
  private let guardLock = NSLock()
  private var requestTimeout: TimeInterval = 20
  private var resourceTimeout: TimeInterval = 30
  private var generation = 0
  private var sessions: [UUID: URLSession] = [:]
  public init(configuration: URLSessionConfiguration = .ephemeral) {
    lanTrust = nil
    configurationProvider = { configuration.copy() as! URLSessionConfiguration }
  }
  /// Used by the private-network route. Failure must propagate; never retry
  /// with a default/direct session when this provider is unavailable.
  public init(configurationProvider: @escaping @Sendable () async throws -> URLSessionConfiguration, requestTimeout: TimeInterval = 20, resourceTimeout: TimeInterval = 30) {
    lanTrust = nil
    self.configurationProvider = configurationProvider
    self.requestTimeout = min(600, max(1, requestTimeout))
    self.resourceTimeout = min(600, max(self.requestTimeout, resourceTimeout))
  }
  /// Trust is scoped to this reviewed LAN receiver, never installed system-wide.
  public init(workServer: WorkAccessConfiguration) throws {
    try workServer.validate()
    guard workServer.network != .tailscale else { throw PrivateNetworkError.disconnected }
    lanTrust = try (workServer.network == .lan || workServer.network == .local) ? LANServerTrust(configuration: workServer) : nil
    configurationProvider = { .ephemeral }
  }
  func verifiesLAN(_ configuration: WorkAccessConfiguration) -> Bool {
    lanTrust == (try? LANServerTrust(configuration: configuration)) && lanTrust != nil
  }
  deinit { sessions.values.forEach { $0.invalidateAndCancel() } }
  public func cancel() {
    guardLock.lock()
    generation += 1
    let old = Array(sessions.values)
    sessions.removeAll()
    guardLock.unlock()
    old.forEach { $0.invalidateAndCancel() }
  }
  private func ticket() -> Int {
    guardLock.lock(); defer { guardLock.unlock() }
    return generation
  }
  private func register(_ session: URLSession, ticket: Int, id: UUID) throws {
    guardLock.lock(); defer { guardLock.unlock() }
    guard ticket == generation else {
      session.invalidateAndCancel()
      throw CancellationError()
    }
    sessions[id] = session
  }
  private func finish(_ id: UUID) {
    guardLock.lock()
    let session = sessions.removeValue(forKey: id)
    guardLock.unlock()
    session?.invalidateAndCancel()
  }
  private func openSession() async throws -> (UUID, URLSession) {
    let version = ticket()
    let configuration = try await configurationProvider()
    try Task.checkCancellation()
    configuration.httpCookieStorage = nil
    if lanTrust?.host == "127.0.0.1" { configuration.connectionProxyDictionary = [:] }
    configuration.httpShouldSetCookies = false
    configuration.urlCredentialStorage = nil
    configuration.urlCache = nil
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    configuration.timeoutIntervalForRequest = requestTimeout
    configuration.timeoutIntervalForResource = resourceTimeout
    let session = URLSession(configuration: configuration, delegate: RedirectBlocker(lanTrust: lanTrust), delegateQueue: nil)
    let id = UUID()
    try register(session, ticket: version, id: id)
    return (id, session)
  }
  /// Exercise only the closed read endpoint with an empty body. A 401 with the
  /// expected bounded error demonstrates reachability, never authorization.
  public func checkReadReceiver(at origin: URL) async throws {
    if let lanTrust, !lanTrust.permits(origin) { throw WalletFailure.core("service_setup_required") }
    guard origin.scheme == "https", origin.host != nil,
      origin.user == nil, origin.password == nil, origin.query == nil,
      origin.fragment == nil, origin.path.isEmpty || origin.path == "/"
    else { throw WalletFailure.core("service_setup_required") }
    let url = origin.appendingPathComponent("devgraph/native-read/v2/requests")
    var request = URLRequest(url: url, timeoutInterval: 8)
    request.httpMethod = "POST"
    request.httpBody = Data("{}".utf8)
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    let (id, session) = try await openSession()
    defer { finish(id) }
    let (bytes, response) = try await session.bytes(for: request, delegate: session.delegate as? URLSessionTaskDelegate)
    guard let response = response as? HTTPURLResponse,
      response.url == url, response.statusCode == 401,
      response.expectedContentLength <= 1024
    else { throw WalletFailure.core("service_rejected_request") }
    var data = Data()
    for try await byte in bytes {
      guard data.count < 1024 else { throw WalletFailure.invalidFile }
      data.append(byte)
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: String],
      value == ["error": "access_denied"]
    else { throw WalletFailure.core("invalid_response") }
  }
  /// Discovery-only fixed metadata GETs. No identity, bearer, cookies or stored
  /// credentials are sent; loopback HTTP is limited to /live for old APIs.
  public func publicServiceMetadata(at origin: URL, path: String) async throws -> Data {
    guard ["/live","/.well-known/devgraph-connection.json"].contains(path),
      origin.path.isEmpty,origin.user == nil,origin.password == nil,origin.query == nil,origin.fragment == nil,
      origin.scheme == "https" || (origin.scheme == "http" && origin.host == "127.0.0.1" && path == "/live"),
      lanTrust == nil || lanTrust!.permits(origin) else { throw WalletFailure.core("service_setup_required") }
    let url=origin.appendingPathComponent(String(path.dropFirst()))
    var request=URLRequest(url:url,timeoutInterval:3);request.httpMethod="GET"
    let (id,session)=try await openSession();defer { finish(id) }
    let (bytes,response)=try await session.bytes(for:request,delegate:session.delegate as? URLSessionTaskDelegate)
    guard let response=response as? HTTPURLResponse,response.statusCode==200,response.url==url,
      response.expectedContentLength<=16384 else { throw WalletFailure.core("invalid_response") }
    var data=Data()
    for try await byte in bytes { guard data.count<16384 else { throw WalletFailure.invalidFile };data.append(byte) }
    return data
  }
  public func request(_ request: URLRequest, maximum: Int = 1_048_576, viewChangedOnConflict: Bool = false) async throws -> Data {
    if let lanTrust, request.url.map({ !lanTrust.permits($0) }) ?? true {
      throw WalletFailure.core("service_setup_required")
    }
    guard request.url?.scheme == "https", request.url?.user == nil, request.url?.password == nil
    else { throw WalletFailure.core("service_setup_required") }
    let (id, session) = try await openSession()
    defer { finish(id) }
    let (bytes, response) = try await session.bytes(for: request, delegate: session.delegate as? URLSessionTaskDelegate)
    guard let response = response as? HTTPURLResponse, response.url == request.url else {
      throw WalletFailure.core("invalid_response")
    }
    if response.statusCode == 401 || response.statusCode == 403 {
      throw WalletFailure.core("access_denied")
    }
    if response.statusCode == 409 && viewChangedOnConflict {
      throw WalletFailure.core("work_view_changed")
    }
    guard (200..<300).contains(response.statusCode) else {
      throw WalletFailure.core("service_rejected_request")
    }
    guard response.expectedContentLength < 0 || response.expectedContentLength <= maximum else {
      throw WalletFailure.invalidFile
    }
    var data = Data()
    for try await byte in bytes {
      guard data.count < maximum else { throw WalletFailure.invalidFile }
      data.append(byte)
    }
    return data
  }
  /// Operator protocols distinguish a definitive rejection from an uncertain
  /// result. Preserve bounded status/body while retaining the same TLS,
  /// redirect, cookie and cancellation boundary as ordinary requests.
  public func exchange(_ request: URLRequest, maximum: Int = 1_048_576) async throws -> PrivateHTTPResponse {
    guard request.url?.scheme == "https", request.url?.user == nil, request.url?.password == nil,
      maximum > 0, maximum <= 1_048_576,
      lanTrust == nil || request.url.map({ lanTrust!.permits($0) }) == true
    else { throw WalletFailure.core("service_setup_required") }
    let (id, session) = try await openSession(); defer { finish(id) }
    let (bytes, response) = try await session.bytes(for: request, delegate: session.delegate as? URLSessionTaskDelegate)
    guard let response = response as? HTTPURLResponse, response.url == request.url,
      response.expectedContentLength < 0 || response.expectedContentLength <= maximum
    else { throw WalletFailure.core("invalid_response") }
    var data = Data()
    for try await byte in bytes {
      guard data.count < maximum else { throw WalletFailure.invalidFile }; data.append(byte)
    }
    return PrivateHTTPResponse(status: response.statusCode, data: data)
  }
}

public struct PrivateHTTPResponse: Sendable {
  public let status: Int
  public let data: Data
  public init(status: Int, data: Data) { self.status = status; self.data = data }
}

extension MembershipConfiguration {
  public static let settingsKey = "membership.provider.configuration.v1"
  public static func proposed(in defaults: UserDefaults = .standard, bundle: Bundle = .main) -> Self? {
    if let data = defaults.data(forKey: settingsKey), !data.isEmpty {
      return try? decodeFile(data)
    }
    return bundled(in: bundle)
  }
  /// A public configuration file proposes a provider; it cannot approve trust,
  /// activate a proof, or contain credentials. Persist only the decoded shape.
  public static func decodeFile(_ data: Data) throws -> Self {
    var strict = AccountRecordJSON(data, maximumBytes: 65_536, maximumDepth: 12)
    try strict.validate()
    guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(value.keys).isSubset(of: ["name", "endpoint", "scope", "trust"]),
      ["name", "endpoint", "trust"].allSatisfy({ value[$0] != nil })
    else { throw WalletFailure.core("service_setup_required") }
    let configuration = try JSONDecoder().decode(Self.self, from: data)
    try configuration.validate()
    return configuration
  }
  public static func bundled(in bundle: Bundle = .main) -> Self? {
    guard let url = bundle.url(forResource: "Membership", withExtension: "json"),
      let data = try? Data(contentsOf: url), data.count <= 65_536,
      let value = try? decodeFile(data)
    else { return nil }
    return value
  }
}
