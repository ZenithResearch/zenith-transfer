#if os(macOS)
import CryptoKit
import Darwin
import Foundation

public enum PublicationFailure: LocalizedError {
  case unavailable, invalid, changed, localSourceRequired
  public var errorDescription: String? {
    switch self {
    case .unavailable: return "Tailscale status could not be read. Open Tailscale on this Mac and refresh."
    case .invalid: return "These publishing settings are not supported. Keep the selected service and choose valid HTTPS ports."
    case .changed: return "The service or Tailscale configuration changed. Refresh and review again."
    case .localSourceRequired: return "This is a registered network address. To review an additional address, select the local Wallet API under Servers & access points."
    }
  }
}

/// Public machine-network observations, not proof of service ownership or authority.
/// A whole listener port is reserved even when only one path is configured on it.
public struct PublicationSnapshot: Sendable, Equatable {
  public let running: Bool
  public let dnsName: String
  public let occupiedPorts: Set<Int>
  public let publicPorts: Set<Int>
  public let revision: String

  public static func decode(status: Data, serve: Data) throws -> Self {
    guard status.count <= 1_048_576, serve.count <= 262_144 else { throw PublicationFailure.invalid }
    var check = OwnerPlanJSON(serve, maximumBytes: 262_144, maximumKeys: 6000, maximumArray: 6000, maximumDepth: 24)
    try check.validate()
    guard let state = try JSONSerialization.jsonObject(with: status) as? [String: Any],
      let own = state["Self"] as? [String: Any], let rawName = own["DNSName"] as? String,
      let config = try JSONSerialization.jsonObject(with: serve) as? [String: Any]
    else { throw PublicationFailure.invalid }
    let name = rawName.hasSuffix(".") ? String(rawName.dropLast()) : rawName
    guard name.utf8.count <= 253,
      name.range(of: "^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\\.ts\\.net$", options: .regularExpression) != nil,
      name.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({ !$0.isEmpty && $0.count <= 63 })
    else { throw PublicationFailure.invalid }
    var occupied: Set<Int> = [], exposed: Set<Int> = []
    func port(_ raw: String) throws -> Int {
      guard let value = Int(raw), String(value) == raw, (1...65535).contains(value) else { throw PublicationFailure.invalid }
      return value
    }
    if let raw = config["TCP"] {
      guard let tcp = raw as? [String: Any] else { throw PublicationFailure.invalid }
      for key in tcp.keys { occupied.insert(try port(key)) }
    }
    for field in ["Web", "AllowFunnel"] {
      guard let raw = config[field] else { continue }
      guard let values = raw as? [String: Any] else { throw PublicationFailure.invalid }
      for (key, value) in values {
        let parts = key.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2, String(parts[0]) == name else { throw PublicationFailure.invalid }
        let number = try port(String(parts[1])); occupied.insert(number)
        if field == "AllowFunnel" {
          guard let enabled = value as? Bool else { throw PublicationFailure.invalid }
          if enabled { exposed.insert(number) }
        }
      }
    }
    let canonical = try OwnerReviewCanonicalJSON.encode(config)
    return Self(running: state["BackendState"] as? String == "Running" && own["Online"] as? Bool == true,
      dnsName: name, occupiedPorts: occupied, publicPorts: exposed,
      revision: OwnerSetupPlan.sha256(Data(name.utf8) + Data([0]) + canonical))
  }
}

/// A proposal is deliberately not a runnable shell command or a connection profile.
/// New origin/certificate/issuer bindings must be prepared by each service adapter.
public struct ServicePublicationReview: Codable, Sendable, Equatable {
  public let schema: String
  public let resourceID: String
  public let serviceID: String
  public let serviceName: String
  public let sourceEndpoint: String
  public let serviceSHA256: String
  public let expectedNetworkRevision: String
  public let tailnetURL: String?
  public let funnelURL: String?
  public let blockers: [String]
  public let authorityChanged: Bool
  enum CodingKeys: String, CodingKey {
    case schema, blockers
    case resourceID = "resource_id", serviceID = "service_id", serviceName = "service_name"
    case sourceEndpoint = "source_endpoint", serviceSHA256 = "service_sha256"
    case expectedNetworkRevision = "expected_network_revision"
    case tailnetURL = "tailnet_url", funnelURL = "funnel_url", authorityChanged = "authority_changed"
  }

  public static func canPrepare(from service: LocalService) -> Bool {
    guard let endpoint = URL(string: service.endpoint), ["http","https"].contains(endpoint.scheme ?? ""),
      endpoint.host == "127.0.0.1", endpoint.port != nil,
      endpoint.user == nil, endpoint.password == nil, endpoint.query == nil, endpoint.fragment == nil,
      endpoint.path.isEmpty else { return false }
    return true
  }

  public static func prepare(service: LocalService, snapshot: PublicationSnapshot,
    tailnet: Bool, privatePort: Int, funnel: Bool, publicPort: Int) throws -> Self {
    guard canPrepare(from:service) else { throw PublicationFailure.localSourceRequired }
    guard tailnet || funnel,
      (!tailnet || (1024...65535).contains(privatePort)),
      (!funnel || [443,8443,10000].contains(publicPort)),
      !(tailnet && funnel && privatePort == publicPort)
    else { throw PublicationFailure.invalid }
    var blockers: [String] = []
    if !snapshot.running { blockers.append("Tailscale is not connected on this Mac.") }
    if tailnet && snapshot.occupiedPorts.contains(privatePort) {
      blockers.append("HTTPS port \(privatePort) already belongs to an existing Tailscale listener. Choose a free port; existing routes will not be replaced.")
    }
    if funnel && snapshot.occupiedPorts.contains(publicPort) {
      blockers.append("Funnel port \(publicPort) is already in use. Publishing it could expose or replace another service. Choose a free supported port or a separate Tailscale node.")
    }
    if service.interface == .privateAPI {
      blockers.append("This private API has no reviewed public-publishing adapter. Select the service’s Wallet API instead.")
    }
    blockers.append("Service-specific owner authorization, external origin and certificate bindings must be prepared before activation. This review does not publish the service.")
    let binding: [String: Any] = ["resource_id":service.resource_id,"instance_id":service.id,
      "endpoint":service.endpoint,"connection":try service.connection.map { try JSONSerialization.jsonObject(with: JSONEncoder().encode($0)) } ?? NSNull()]
    return Self(schema: "zenith.service-publication-review.v1", resourceID: service.resource_id,
      serviceID: service.id, serviceName: service.name, sourceEndpoint: service.endpoint,
      serviceSHA256: OwnerSetupPlan.sha256(try OwnerReviewCanonicalJSON.encode(binding)),
      expectedNetworkRevision: snapshot.revision,
      tailnetURL: tailnet ? "https://\(snapshot.dnsName):\(privatePort)" : nil,
      funnelURL: funnel ? "https://\(snapshot.dnsName):\(publicPort)" : nil,
      blockers: blockers, authorityChanged: false)
  }
}

/// Closed read-only CLI adapter. No shell, login, reset, Serve or Funnel mutation.
public enum TailscalePublicationInspector {
  static func commandEnvironment(_ inherited: [String: String]) -> [String: String] {
    var environment = inherited
    // The macOS executable is also a GUI app. A graphical parent has no
    // terminal hints, so request the vendor's CLI mode explicitly.
    environment["TAILSCALE_BE_CLI"] = "1"
    return environment
  }
  public static func inspect() async throws -> PublicationSnapshot {
    try await Task.detached {
      let status = try read(["status","--json"], maximum: 1_048_576)
      let serve = try read(["serve","status","--json"], maximum: 262_144)
      return try PublicationSnapshot.decode(status: status, serve: serve)
    }.value
  }
  private static func read(_ arguments: [String], maximum: UInt64) throws -> Data {
    let executable = URL(fileURLWithPath: "/Applications/Tailscale.app/Contents/MacOS/Tailscale")
    guard FileManager.default.isExecutableFile(atPath: executable.path) else { throw PublicationFailure.unavailable }
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions:0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let file = directory.appendingPathComponent("status.json")
    guard FileManager.default.createFile(atPath: file.path, contents: nil, attributes: [.posixPermissions:0o600]) else { throw PublicationFailure.unavailable }
    let output = try FileHandle(forWritingTo: file); defer { try? output.close() }
    let process = Process(); process.executableURL = executable; process.arguments = arguments
    process.environment = commandEnvironment(ProcessInfo.processInfo.environment)
    process.standardInput = FileHandle.nullDevice; process.standardOutput = output; process.standardError = FileHandle.nullDevice
    try process.run()
    let deadline = ProcessInfo.processInfo.systemUptime + 10
    while process.isRunning {
      if ProcessInfo.processInfo.systemUptime >= deadline || ((try? FileManager.default.attributesOfItem(atPath:file.path)[.size] as? NSNumber)?.uint64Value ?? maximum + 1) > maximum {
        process.terminate()
        if process.isRunning { Darwin.kill(process.processIdentifier,SIGKILL) }
        throw PublicationFailure.unavailable
      }
      Thread.sleep(forTimeInterval:0.02)
    }
    guard process.terminationStatus == 0 else { throw PublicationFailure.unavailable }
    return try OwnerSetupInspector.privateData(file, maximum: Int(maximum))
  }
}
#endif
