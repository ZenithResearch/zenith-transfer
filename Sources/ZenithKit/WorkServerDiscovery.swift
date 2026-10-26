import Foundation

/// Fetch only public verification settings. Discovery sends no Wallet identity
/// and cannot save settings, install trust, or grant access.
public enum WorkServerDiscovery {
  public static func discover(_ address: String, network: WorkNetwork? = nil,
    transport: PrivateTransport? = nil) async throws -> WorkAccessConfiguration {
    let origin = try WorkServerSettings.address(address)
    guard network == nil || network == .tailscale else { throw WorkServerSetupError.profile }
    // Private discovery requires the caller's embedded route, just like reads.
    guard network != .tailscale || transport != nil else { throw PrivateNetworkError.disconnected }
    let url = origin.appendingPathComponent(".well-known/devgraph-connection.json")
    let data = try await (transport ?? PrivateTransport()).request(URLRequest(url: url), maximum: WorkServerSettings.maximumFileBytes)
    let configuration = try WorkServerSettings.decode(data)
    guard configuration.origin == origin.absoluteString,
      configuration.network == nil || configuration.network == network else {
      throw WorkServerSetupError.profile
    }
    if network == .tailscale {
      let routed = try WorkAccessConfiguration(name: configuration.name, receiver: configuration.receiver,
        issuer: configuration.issuer, keyID: configuration.authority.key_id,
        publicKey: configuration.authority.public_key, network: .tailscale)
      return try await routed.resolveService(transport: transport!)
    }
    return try await configuration.resolveService(transport: transport ?? PrivateTransport())
  }
}
