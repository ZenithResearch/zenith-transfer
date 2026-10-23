import CryptoKit
import Foundation
import Security

/// A certificate fingerprint from the operator's separately supplied connection
/// file. The exact leaf, hostname, dates and server-use policy must all validate.
/// This never trusts a certificate learned from a failed network connection.
struct LANServerTrust: Sendable, Equatable {
  let host: String
  let port: Int
  let fingerprint: String

  init(configuration: WorkAccessConfiguration) throws {
    try configuration.validate()
    guard configuration.network == .lan || configuration.network == .local, let host = configuration.receiver.host,
      let fingerprint = configuration.tls_certificate_sha256
    else { throw WalletFailure.core("service_setup_required") }
    self.host = host.lowercased()
    port = configuration.receiver.port ?? 443
    self.fingerprint = fingerprint
  }

  func permits(_ url: URL) -> Bool {
    url.scheme == "https" && url.host?.lowercased() == host
      && (url.port ?? 443) == port && url.user == nil && url.password == nil
  }

  func accepts(_ trust: SecTrust, host: String, port: Int) -> Bool {
    guard host.lowercased() == self.host, port == self.port,
      let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
      let leaf = chain.first,
      SHA256.hash(data: SecCertificateCopyData(leaf) as Data)
        .map({ String(format: "%02x", $0) }).joined() == fingerprint
    else { return false }
    // Add an exact, per-connection anchor; retain SSL hostname, expiry, key-use
    // and signature checks. No network-based AIA fetching or trust fallback.
    guard SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, self.host as CFString)) == errSecSuccess,
      SecTrustSetAnchorCertificates(trust, [leaf] as CFArray) == errSecSuccess,
      SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
      SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess
    else { return false }
    return SecTrustEvaluateWithError(trust, nil)
  }
}
