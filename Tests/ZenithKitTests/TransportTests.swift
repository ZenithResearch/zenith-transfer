import XCTest

@testable import ZenithKit

private final class ResponseProtocol: URLProtocol {
  static let guardLock = NSLock()
  static var handler: ((URLRequest) -> (Int, Data))?
  override class func canInit(with request: URLRequest) -> Bool { true }
  override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
  override func startLoading() {
    Self.guardLock.lock()
    let handler = Self.handler
    Self.guardLock.unlock()
    guard let handler else { return }
    let (status, data) = handler(request)
    guard let url = request.url,
      let response = HTTPURLResponse(
        url: url, statusCode: status, httpVersion: "HTTP/1.1",
        headerFields: ["Content-Length": String(data.count)])
    else { return }
    client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
    client?.urlProtocol(self, didLoad: data)
    client?.urlProtocolDidFinishLoading(self)
  }
  override func stopLoading() {}
}
final class TransportTests: XCTestCase {
  func testOperatorExchangePreservesBoundedDefinitiveRejection() async throws {
    let bytes = Data(#"{"error":"operator_assignment_changed"}"#.utf8)
    let response = try await transport(status:409,data:bytes).exchange(URLRequest(url:URL(string:"https://example.test/devgraph/access-operator/v1/actions")!),maximum:1024)
    XCTAssertEqual(response.status,409); XCTAssertEqual(response.data,bytes)
    do {
      _ = try await transport(status:409,data:Data(repeating:65,count:1025)).exchange(URLRequest(url:URL(string:"https://example.test")!),maximum:1024)
      XCTFail("Bounded errors")
    } catch { }
  }
  func testDiscoveryIsPublicBoundedAndCannotMoveTheReceiver() async throws {
    let config = try WorkAccessConfiguration(name:"Remote test",receiver:URL(string:"https://example.test")!,issuer:"test",keyID:"key",publicKey:String(repeating:"12",count:32))
    let encoded = try JSONEncoder().encode(config)
    let discovered = try await WorkServerDiscovery.discover("https://example.test",transport:transport(status:200,data:encoded))
    XCTAssertEqual(discovered,config)
    do {
      _ = try await WorkServerDiscovery.discover("https://different.test",transport:transport(status:200,data:encoded))
      XCTFail("Discovery cannot select a different receiver")
    } catch { }
    do {
      _ = try await WorkServerDiscovery.discover("https://example.test",transport:transport(status:302,data:encoded))
      XCTFail("No redirect")
    } catch { }
  }
  func testRequestRecordSurvivesRelaunchWithoutCreatingAnotherID() throws {
    let directory=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:directory) }
    let store=try WorkAccessRequestStore(directory:directory)
    let first=try store.begin(receiver:"https://example.test",subject:String(repeating:"11",count:32),installation:String(repeating:"22",count:16))
    let reloaded=try WorkAccessRequestStore(directory:directory).begin(receiver:first.receiver,subject:first.subject,installation:first.installation)
    XCTAssertEqual(first,reloaded)
    XCTAssertNil(try store.existing(receiver:"https://other.test",subject:first.subject,installation:first.installation))
    let files=try FileManager.default.contentsOfDirectory(at:directory,includingPropertiesForKeys:nil)
    XCTAssertEqual(files.count,1)
    let fields=try JSONSerialization.jsonObject(with:Data(contentsOf:files[0])) as! [String:Any]
    XCTAssertEqual(Set(fields.keys),["receiver","subject","installation","requestID"])
  }
  func testTailscaleDiscoveryPreservesVerificationAndSavedRoute() async throws {
    let config = try WorkAccessConfiguration(name: "Private server", receiver: URL(string: "https://example.test")!,
      issuer: "test", keyID: "key", publicKey: String(repeating: "12", count: 32))
    let discovered = try await WorkServerDiscovery.discover("https://example.test", network: .tailscale,
      transport: transport(status: 200, data: JSONEncoder().encode(config)))
    XCTAssertEqual(discovered.network, .tailscale)
    XCTAssertEqual(discovered.authority, config.authority)
    XCTAssertEqual(discovered.receiver, config.receiver)
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    try WorkServerStore(directory: directory).save(discovered, replacing: nil)
    XCTAssertEqual(try WorkServerStore(directory: directory).load(), discovered)
  }
  func testTailscaleDiscoveryRequiresPrivateTransportAndDoesNotFallback() async throws {
    do {
      _ = try await WorkServerDiscovery.discover("https://example.test", network: .tailscale)
      XCTFail("A private route must be supplied")
    } catch { XCTAssertEqual(error as? PrivateNetworkError, .disconnected) }
    let disconnected = PrivateTransport(configurationProvider: { throw PrivateNetworkError.disconnected })
    do {
      _ = try await WorkServerDiscovery.discover("https://example.test", network: .tailscale, transport: disconnected)
      XCTFail("A disconnected private route must fail")
    } catch { XCTAssertEqual(error as? PrivateNetworkError, .disconnected) }
  }
  func testDiscoveryHonorsPrivateProfilesAndRejectsReceiverChanges() async throws {
    let config = try WorkAccessConfiguration(name: "Private server", receiver: URL(string: "https://example.test")!,
      issuer: "test", keyID: "key", publicKey: String(repeating: "12", count: 32), network: .tailscale)
    let encoded = try JSONEncoder().encode(config)
    let discovered = try await WorkServerDiscovery.discover("https://example.test", network: .tailscale,
      transport: transport(status: 200, data: encoded))
    XCTAssertEqual(discovered, config)
    for (address, network) in [("https://example.test", WorkNetwork?.none),
      ("https://different.test", WorkNetwork?.some(.tailscale))] {
      do {
        _ = try await WorkServerDiscovery.discover(address, network: network,
          transport: transport(status: 200, data: encoded))
        XCTFail("Discovery cannot change the selected route or receiver")
      } catch { XCTAssertTrue(error is WorkServerSetupError) }
    }
    do {
      _ = try await WorkServerDiscovery.discover("https://example.test", network: .tailscale,
        transport: transport(status: 302, data: encoded))
      XCTFail("Private discovery cannot follow redirects")
    } catch { XCTAssertEqual(error as? WalletFailure, .core("service_rejected_request")) }
  }
  func testReadConnectionRequiresSeparateIssuerPin() throws {
    let old = Data(#"{"name":"Work","issuer":"example","receiver":"https://example.test"}"#.utf8)
    XCTAssertThrowsError(try JSONDecoder().decode(WorkAccessConfiguration.self, from: old))
    var value: [String: Any] = ["name":"Work", "issuer":"example", "receiver":"https://example.test",
      "authority":["issuer":"example", "key_id":"read-key", "public_key":String(repeating:"12", count:32),
      "receiver":"https://example.test", "audience":"devgraph"]]
    let config = try JSONDecoder().decode(WorkAccessConfiguration.self, from: JSONSerialization.data(withJSONObject: value))
    XCTAssertNoThrow(try config.validate())
    XCTAssertNil(config.network)
    value["network"] = "tailscale"
    let privateConfig = try JSONDecoder().decode(WorkAccessConfiguration.self, from: JSONSerialization.data(withJSONObject: value))
    XCTAssertEqual(privateConfig.network, .tailscale)
    XCTAssertNoThrow(try privateConfig.validate())
    value["receiver"] = "https://other.test"
    let wrong = try JSONDecoder().decode(WorkAccessConfiguration.self, from: JSONSerialization.data(withJSONObject: value))
    XCTAssertThrowsError(try wrong.validate())
  }
  private func transport(status: Int, data: Data) -> PrivateTransport {
    ResponseProtocol.guardLock.lock()
    ResponseProtocol.handler = { request in
      if request.url?.path == "/.well-known/devgraph-service.json" { return (404, Data()) }
      return (status, data)
    }
    ResponseProtocol.guardLock.unlock()
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [ResponseProtocol.self]
    return PrivateTransport(configuration: configuration)
  }
  func testRejectsPlainHTTPBeforeDispatch() async throws {
    let client = transport(status: 200, data: Data())
    do {
      _ = try await client.request(URLRequest(url: URL(string: "http://example.test")!))
      XCTFail("HTTP must fail")
    } catch { XCTAssertEqual(error as? WalletFailure, .core("service_setup_required")) }
  }
  func testRejectsOversizedResponseAndRedactsDenial() async throws {
    let url = URL(string: "https://example.test")!
    do {
      _ = try await transport(status: 200, data: Data(repeating: 65, count: 33)).request(
        URLRequest(url: url), maximum: 32)
      XCTFail("Unbounded response")
    } catch { XCTAssertEqual(error as? WalletFailure, .invalidFile) }
    do {
      _ = try await transport(status: 401, data: Data("sensitive server detail".utf8)).request(
        URLRequest(url: url))
      XCTFail("Denied response")
    } catch {
      XCTAssertEqual(error as? WalletFailure, .core("access_denied"))
      XCTAssertFalse(error.localizedDescription.contains("sensitive"))
    }
  }
  func testRedirectIsNeverAcceptedAsCredentialResponse() async throws {
    do {
      _ = try await transport(status: 302, data: Data()).request(
        URLRequest(url: URL(string: "https://example.test")!))
      XCTFail("Redirect accepted")
    } catch { XCTAssertEqual(error as? WalletFailure, .core("service_rejected_request")) }
  }
  func testRejectsMutationScopeBeforeConsent() throws {
    let data = Data(
      #"{"scope":"devgraph.work.read","operations":["transition"],"relationship_types":["parent"],"work_kinds":["Task"],"include_archived":false}"#
        .utf8)
    let grant = try JSONDecoder().decode(WorkReadGrant.self, from: data)
    XCTAssertThrowsError(try grant.validate())
  }
  func testConnectionProbeSendsNoIdentityOrCredential() async throws {
    ResponseProtocol.guardLock.lock()
    ResponseProtocol.handler = { request in
      XCTAssertEqual(request.url?.absoluteString, "https://example.test/devgraph/native-read/v2/requests")
      XCTAssertEqual(request.httpMethod, "POST")
      XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))
      XCTAssertNil(request.value(forHTTPHeaderField: "Cookie"))
      var body = request.httpBody ?? Data()
      if let stream = request.httpBodyStream {
        stream.open(); defer { stream.close() }
        var buffer = [UInt8](repeating: 0, count: 64)
        let count = stream.read(&buffer, maxLength: buffer.count)
        if count > 0 { body = Data(buffer.prefix(count)) }
      }
      XCTAssertEqual(body, Data("{}".utf8))
      return (401, Data(#"{"error":"access_denied"}"#.utf8))
    }
    ResponseProtocol.guardLock.unlock()
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [ResponseProtocol.self]
    try await PrivateTransport(configuration: configuration).checkReadReceiver(at: URL(string: "https://example.test")!)
  }
  func testConnectionProbeRejectsWrongServiceRedirectAndOversizedResponse() async throws {
    for (status, body) in [(200, Data()), (302, Data()), (503, Data()),
      (401, Data(#"{"error":"other_service"}"#.utf8)), (401, Data(repeating: 65, count: 1025))] {
      do {
        try await transport(status: status, data: body).checkReadReceiver(at: URL(string: "https://example.test")!)
        XCTFail("Unexpected probe success for \(status)")
      } catch { XCTAssertTrue(error is WalletFailure) }
    }
  }
  func testNetworkGuidanceDoesNotMisdiagnoseTLSOrCancellation() {
    let timeout = WorkConnectionFailure(code: .timedOut, network: .tailscale)
    XCTAssertTrue(timeout.localizedDescription.contains("through Tailscale"))
    let publicTimeout = WorkConnectionFailure(code: .timedOut, network: nil)
    XCTAssertFalse(publicTimeout.localizedDescription.contains("Tailscale"))
    let certificate = WorkConnectionFailure(code: .serverCertificateUntrusted, network: .tailscale)
    XCTAssertTrue(certificate.localizedDescription.contains("could not be verified"))
    let cancelled = WorkConnectionFailure(code: .cancelled, network: .tailscale)
    XCTAssertFalse(cancelled.localizedDescription.contains("Can’t reach"))
  }

}
