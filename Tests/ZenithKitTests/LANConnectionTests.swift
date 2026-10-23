import CryptoKit
import Security
import XCTest
@testable import ZenithKit

final class LANConnectionTests: XCTestCase {
  private let host = "work.example.local"
  private func certificate(_ name: String = "lan-server") throws -> SecCertificate {
    let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "der"))
    return try XCTUnwrap(SecCertificateCreateWithData(nil, Data(contentsOf: url) as CFData))
  }
  private func configuration(_ certificate: SecCertificate, host: String = "work.example.local") throws -> WorkAccessConfiguration {
    let fingerprint = SHA256.hash(data: SecCertificateCopyData(certificate) as Data)
      .map({ String(format: "%02x", $0) }).joined()
    return try WorkAccessConfiguration(name: "Example LAN", receiver: URL(string: "https://\(host):9444")!,
      issuer: "example", keyID: "example", publicKey: String(repeating: "12", count: 32),
      network: .lan, tlsCertificateSHA256: fingerprint)
  }
  private func trust(_ certificate: SecCertificate, at date: Date = Date(timeIntervalSince1970: 1_792_000_000)) throws -> SecTrust {
    var trust: SecTrust?
    XCTAssertEqual(SecTrustCreateWithCertificates(certificate, SecPolicyCreateSSL(true, host as CFString), &trust), errSecSuccess)
    let value = try XCTUnwrap(trust)
    XCTAssertEqual(SecTrustSetVerifyDate(value, date as CFDate), errSecSuccess)
    return value
  }
  func testExactCertificateStillRequiresHostnameDatesAndServerUse() throws {
    let cert = try certificate()
    let pin = try LANServerTrust(configuration: configuration(cert))
    XCTAssertTrue(pin.accepts(try trust(cert), host: host, port: 9444))
    XCTAssertFalse(pin.accepts(try trust(cert), host: "other.local", port: 9444))
    XCTAssertFalse(pin.accepts(try trust(cert), host: host, port: 443))
    let wrongHost = try LANServerTrust(configuration: configuration(cert, host: "other.local"))
    XCTAssertFalse(wrongHost.accepts(try trust(cert), host: "other.local", port: 9444))
    XCTAssertFalse(pin.accepts(try trust(cert, at: Date(timeIntervalSince1970: 0)), host: host, port: 9444))
    XCTAssertFalse(pin.accepts(try trust(cert, at: Date(timeIntervalSince1970: 2_000_000_000)), host: host, port: 9444))
    let clientOnly = try certificate("lan-client-only")
    XCTAssertFalse(try LANServerTrust(configuration: configuration(clientOnly))
      .accepts(trust(clientOnly), host: host, port: 9444))
    XCTAssertFalse(pin.accepts(try trust(clientOnly), host: host, port: 9444))
  }
  func testLANProfileCannotLosePinOrChangeRouteSilently() throws {
    let config = try configuration(certificate())
    XCTAssertEqual(try WorkServerSettings.decode(JSONEncoder().encode(config)), config)
    var json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(config)) as! [String: Any]
    json.removeValue(forKey: "tls_certificate_sha256")
    XCTAssertThrowsError(try WorkServerSettings.decode(JSONSerialization.data(withJSONObject: json)))
    for network in ["tailscale", "unexpected"] {
      json["network"] = network
      json["tls_certificate_sha256"] = config.tls_certificate_sha256
      XCTAssertThrowsError(try WorkServerSettings.decode(JSONSerialization.data(withJSONObject: json)))
    }
    let transport = try PrivateTransport(workServer: config)
    XCTAssertTrue(transport.verifiesLAN(config))
    XCTAssertFalse(PrivateTransport().verifiesLAN(config))
    XCTAssertTrue(WorkConnectionFailure(code: .timedOut, network: .lan).localizedDescription.contains("same Wi-Fi"))
    XCTAssertFalse(WorkConnectionFailure(code: .serverCertificateUntrusted, network: .lan).localizedDescription.contains("Wi-Fi"))
  }
  func testLANTransportRejectsOtherOriginBeforeDispatch() async throws {
    let transport = try PrivateTransport(workServer: configuration(certificate()))
    for url in ["http://work.example.local:9444", "https://work.example.local", "https://other.local:9444"] {
      do {
        _ = try await transport.request(URLRequest(url: URL(string: url)!))
        XCTFail("Unexpected dispatch")
      } catch { XCTAssertEqual(error as? WalletFailure, .core("service_setup_required")) }
    }
  }
  /// Optional operator qualification: real TLS and native URLSession, no identity,
  /// membership or credential. This is not a substitute for the iPhone Wi-Fi test.
  func testInstalledLANProbeWhenConfigured() async throws {
    guard let path = ProcessInfo.processInfo.environment["ZENITH_LAN_TEST_PROFILE"] else {
      throw XCTSkip("No operator-provided LAN receiver for this run")
    }
    let config = try WorkServerSettings.readFile(URL(fileURLWithPath: path))
    try await PrivateTransport(workServer: config).checkReadReceiver(at: config.receiver)
    let wrong = try WorkAccessConfiguration(name: config.name, receiver: config.receiver,
      issuer: config.issuer, keyID: config.authority.key_id, publicKey: config.authority.public_key,
      network: .lan, tlsCertificateSHA256: String(repeating: "00", count: 32))
    do {
      try await PrivateTransport(workServer: wrong).checkReadReceiver(at: wrong.receiver)
      XCTFail("Wrong certificate accepted")
    } catch {
      let code = try XCTUnwrap((error as? URLError)?.code)
      XCTAssertTrue([URLError.Code.cancelled, .userCancelledAuthentication, .serverCertificateUntrusted].contains(code))
    }
  }
}
