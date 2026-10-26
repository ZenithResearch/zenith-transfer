import Foundation

/// Discovery is advisory, not issuer trust or member access. Only visible peers
/// are considered; no subnet scan, control-plane token, identity or credential.
public enum TailnetServerDiscovery {
  public static let bootstrapPorts = [443, 9443]
  public static func candidates(status data: Data) throws -> [URL] {
    struct Status: Decodable {
      struct Peer: Decodable { let DNSName: String?; let Online: Bool? }
      let BackendState: String
      let Peer: [String: Peer]?
    }
    guard data.count <= 4_194_304 else { throw PrivateNetworkError.invalidStatus }
    let status = try JSONDecoder().decode(Status.self, from: data)
    guard status.BackendState == "Running" else { throw PrivateNetworkError.disconnected }
    var hosts = Set<String>()
    for peer in (status.Peer ?? [:]).values where peer.Online != false {
      guard let name = peer.DNSName else { continue }
      let host = name.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
      guard host.utf8.count <= 253, host.hasSuffix(".ts.net"),
        host.split(separator: ".").count >= 4,
        host.split(separator: ".").allSatisfy({ !$0.isEmpty && $0.count <= 63 && $0.first != "-" && $0.last != "-" && $0.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 } }) else { continue }
      hosts.insert(host)
    }
    // Deterministic bound: callers can enter another known URL manually on
    // larger networks. Never retain the full status document or peer keys.
    return hosts.sorted().prefix(64).flatMap { host in
      bootstrapPorts.compactMap { URL(string: "https://" + host + ($0 == 443 ? "" : ":\($0)")) }
    }
  }

  public static func advertisedOrigins(_ data: Data, at origin: URL) throws -> [URL] {
    struct Directory: Decodable { let schema: String; let origins: [String] }
    guard data.count <= 16384 else { throw WorkServerSetupError.profile }
    let directory = try JSONDecoder().decode(Directory.self, from: data)
    guard directory.schema == "zenith.service-directory.v1", directory.origins.count <= 32 else { throw WorkServerSetupError.profile }
    return try directory.origins.map {
      let url = try WorkServerSettings.address($0)
      // An advertisement cannot cause arbitrary network calls or select a
      // different device. Every advertised port still needs a valid profile.
      guard url.host?.lowercased() == origin.host?.lowercased() else { throw WorkServerSetupError.profile }
      return url
    }
  }

  public typealias Probe = @Sendable (URL) async -> [WorkAccessConfiguration]
  public static func scan(_ origins: [URL], probe: @escaping Probe) async throws -> [WorkAccessConfiguration] {
    let candidates = Array(Set(origins)).sorted { $0.absoluteString < $1.absoluteString }.prefix(128)
    var result: [String: WorkAccessConfiguration] = [:]
    // Four concurrent probes, cancellation observed between bounded batches.
    let all = Array(candidates)
    for offset in stride(from: 0, to: all.count, by: 4) {
      try Task.checkCancellation()
      let batch = Array(all[offset..<min(offset+4, all.count)])
      let found = await withTaskGroup(of: [WorkAccessConfiguration].self) { group in
        for url in batch { group.addTask { await probe(url) } }
        var values: [WorkAccessConfiguration] = []
        for await rows in group { values.append(contentsOf: rows) }
        return values
      }
      for config in found { result[config.origin] = config }
    }
    try Task.checkCancellation()
    return result.values.sorted { $0.name == $1.name ? $0.origin < $1.origin : $0.name < $1.name }
  }

  public static func scan(_ origins: [URL], transport: PrivateTransport) async throws -> [WorkAccessConfiguration] {
    try await scan(origins) { origin in
      var addresses = [origin]
      if let bytes = try? await transport.request(URLRequest(url: origin.appendingPathComponent(".well-known/zenith-services.json")), maximum: 16384),
        let published = try? advertisedOrigins(bytes, at: origin) { addresses += published }
      var found: [WorkAccessConfiguration] = []
      for address in Set(addresses) {
        if Task.isCancelled { return [] }
        if let config = try? await WorkServerDiscovery.discover(address.absoluteString, network: .tailscale, transport: transport) { found.append(config) }
      }
      return found
    }
  }
}
