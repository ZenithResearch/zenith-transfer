#if os(macOS)
import Foundation
import CryptoKit
import ZenithKit

extension WorkAccessConfiguration {
  /// Native management never negotiates or falls back over HTTPS.
  func resolveForLocalManagement() async throws -> Self {
    let rpc = try LocalAdminRPC.discover(configuration: self)
    let inspected = try await rpc.call(operation: "inspect", body: Data("{}".utf8))
    guard inspected.status == 200,
      let value = try JSONSerialization.jsonObject(with: inspected.data) as? [String:Any],
      value["transport"] as? String == "local-secs-rpc",
      value["credential_administration"] as? Bool == true else { throw LocalAdminRPCError.changed }
    guard let binding = value["service_access_point"] else { return try withServiceAccessPoint(nil) }
    let wrapper: [String:Any] = ["schema":"devgraph.service-access-point.v1", "binding":binding]
    return try withServiceAccessPoint(ServiceAccessPoint.decode(JSONSerialization.data(withJSONObject: wrapper), configuration: self))
  }
}

/// The OS registry's graph ID groups interfaces. It is discovery metadata, not
/// authorization: each management route must still pass its fixed local RPC
/// binding, issuer pin, Wallet proof and receiver checks.
struct TransferLogicalService: Identifiable, Equatable {
  let graphID: String
  let servers: [LocalService]
  var id: String { "graph:" + graphID }
  var name: String { servers.first?.name ?? "DevGraph" }
  var walletServers: [LocalService] { servers.filter { $0.interface == .walletAPI } }
  var hasConsistentAuthority: Bool {
    let keys = walletServers.compactMap(\.connection).map {
      [$0.issuer, $0.authority.key_id, $0.authority.public_key, $0.authority.audience].joined(separator: "\n")
    }
    return Set(keys).count == 1 && Set(servers.map(\.id)).count == servers.count
  }
  var screenID: String {
    // A changed pin, route or interface must create a fresh session. No active
    // editor is retargeted when discovery refreshes underneath it.
    let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
    let parts = servers.map { $0.id + ":" + ((try? encoder.encode($0.connection)).map { String(decoding: $0, as: UTF8.self) } ?? "") }
    return id + ":" + SHA256.hash(data: Data(parts.joined(separator: "\n").utf8)).map { String(format: "%02x", $0) }.joined()
  }
  static func groups(_ services: [LocalService]) -> [Self] {
    Dictionary(grouping: services, by: \.resource_id).map { graph, values in
      Self(graphID: graph, servers: values.sorted { $0.id < $1.id })
    }.sorted { $0.name == $1.name ? $0.id < $1.id : $0.name < $1.name }
  }
  func contains(_ resource: RegisteredResource) -> Bool {
    // Never merge unrelated saved profiles just because names/hosts match.
    servers.contains { $0.connection == (try? resource.configuration.withServiceAccessPoint(nil)) }
  }
}

/// A temporary read plan, never persisted authority. Keep old stores visible
/// alongside the canonical provider; aliases of the same store are read once.
struct ServiceInboxRoutePlan {
  struct Candidate {
    let configuration: WorkAccessConfiguration
    let retained: Bool
  }
  struct Route {
    let configuration: WorkAccessConfiguration
    let origins: [String]
  }
  static func make(_ candidates: [Candidate]) throws -> [Route] {
    try Dictionary(grouping: candidates, by: { $0.configuration.authorityOrigin }).map { _, values in
      guard let first = values.first,
        values.allSatisfy({ $0.configuration.credentialAuthority == first.configuration.credentialAuthority }),
        Set(values.compactMap { $0.configuration.serviceID }).count <= 1 else { throw NativeGrantError.changed }
      let ordered = values.sorted {
        let a = $0.retained ? 0 : $0.configuration.serviceID != nil ? 1 : 2
        let b = $1.retained ? 0 : $1.configuration.serviceID != nil ? 1 : 2
        return a == b ? $0.configuration.origin < $1.configuration.origin : a < b
      }
      return Route(configuration: ordered[0].configuration, origins: Set(values.map { $0.configuration.origin }).sorted())
    }.sorted { $0.configuration.authorityOrigin < $1.configuration.authorityOrigin }
  }
}

/// Origin-qualified keys keep legacy request-ID collisions distinct. Canonical
/// aliases use one authority key and are loaded only once by the session model.
struct ServiceInboxRow: Identifiable {
  enum Kind { case request, grant }
  let authority: String
  let kind: Kind
  let raw: [String: Any]
  var id: String { authority + "\n" + (kind == .request ? "request" : "grant") + "\n" + (raw["request_id"] as? String ?? "") + "\n" + (kind == .grant ? raw["assignment_digest"] as? String ?? "" : "") }
  var subject: String { raw["subject_public_key"] as? String ?? "Unknown" }
}

struct ServiceInboxSnapshot {
  private(set) var requests: [ServiceInboxRow] = []
  private(set) var grants: [ServiceInboxRow] = []
  private(set) var next: String?
  private(set) var total = 0
  private var policyDigest: String?
  mutating func accept(_ inbox: NativeOperatorInbox, authority: String, append: Bool) throws {
    if append, let policyDigest, policyDigest != inbox.digest { throw NativeGrantError.changed }
    let incoming = inbox.requests.map { ServiceInboxRow(authority: authority, kind: .request, raw: $0.raw) }
    // Pagination can overlap during a concurrent decision. Identical IDs with
    // changed contents require a fresh snapshot, never silent replacement.
    var rows = append ? requests : []
    for row in incoming {
      if let old = rows.first(where: { $0.id == row.id }) {
        guard GrantJSON.equal(old.raw, row.raw) else { throw NativeGrantError.changed }
      } else { rows.append(row) }
    }
    requests = rows.sorted { $0.id < $1.id }
    grants = inbox.activeGrants.map { ServiceInboxRow(authority: authority, kind: .grant, raw: $0) }
    next = inbox.next; total = inbox.total; policyDigest = inbox.digest
  }
}
#endif
