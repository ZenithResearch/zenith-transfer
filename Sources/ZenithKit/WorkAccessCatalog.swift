import CryptoKit
import Foundation

/// Stable typed anchors, evaluated by Devgraph against containment at each access.
public struct WorkResourcePath: Codable, Sendable, Hashable {
  public let schema: String
  public let path: [String]
  public init(path: [String]) throws {
    self.schema = "devgraph.resource-path.v1"; self.path = path
    try validate()
  }
  public func validate() throws {
    let order = ["Arena", "Initiative", "Project"]
    var previous = -1
    guard schema == "devgraph.resource-path.v1", (1...3).contains(path.count) else {
      throw WalletFailure.core("unsupported_read_scope")
    }
    for anchor in path {
      let pieces = anchor.split(separator: "/", omittingEmptySubsequences: false)
      guard pieces.count == 2, let rank = order.firstIndex(of: String(pieces[0])), rank > previous,
        validWorkID(String(pieces[1])) else { throw WalletFailure.core("unsupported_read_scope") }
      previous = rank
    }
  }
  public var summary: String { path.joined(separator: " → ") }
}
public struct WorkAccessPreset: Codable, Sendable, Identifiable, Equatable {
  public let id: String
  public let name: String
  public let version: UInt64
  public let read_operations: [String]
  public let write_operations: [String]
}
public struct WorkScopeOption: Codable, Sendable, Identifiable, Equatable {
  public let resource_path: WorkResourcePath
  public let resource: String
  public let title: String
  public let parent: String?
  public var id: String { resource }
  public var kind: String { resource.split(separator: "/").first.map(String.init) ?? "" }
}
public struct WorkAccessCatalog: Decodable, Sendable {
  public let schema: String
  public let issuer: String
  public let receiver: String
  public let revision: UInt64
  public let catalog_digest_sha256: String
  public let presets: [WorkAccessPreset]
  public let scopes: [WorkScopeOption]
  public let scope_semantics: String

  public static func decode(_ data: Data, receiver: String, issuer: String) throws -> Self {
    guard data.count <= 262_144,
      var raw = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(raw.keys) == ["schema", "issuer", "receiver", "revision", "presets", "published_paths",
        "policy_digest_sha256", "catalog_digest_sha256", "scopes", "scope_semantics"]
    else { throw WalletFailure.core("invalid_access_catalog") }
    guard let presets = raw["presets"] as? [[String:Any]],
      let scopes = raw["scopes"] as? [[String:Any]],
      let publications = raw["published_paths"] as? [[String:Any]],
      publications.count <= 16,
      presets.allSatisfy({ Set($0.keys) == ["id","name","version","read_operations","write_operations"] }),
      scopes.allSatisfy({ row in
        guard Set(row.keys) == ["resource_path","resource","title","parent"],
          let path = row["resource_path"] as? [String:Any] else { return false }
        return Set(path.keys) == ["schema","path"]
      }),
      publications.allSatisfy({ row in
        guard Set(row.keys) == ["resource_path","discover_descendants"],
          row["discover_descendants"] is Bool,
          let path = row["resource_path"] as? [String:Any] else { return false }
        return Set(path.keys) == ["schema","path"]
      }) else { throw WalletFailure.core("invalid_access_catalog") }
    let value = try JSONDecoder().decode(Self.self, from: data)
    guard value.schema == "devgraph.access-catalog.v1", value.receiver == receiver,
      value.issuer == issuer, value.revision > 0, value.revision <= 9_007_199_254_740_991,
      value.scope_semantics == "current_resources_at_access",
      value.catalog_digest_sha256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
      value.presets.count <= 16, Set(value.presets.map(\.id)).count == value.presets.count,
      value.scopes.count <= 2000, Set(value.scopes.map(\.id)).count == value.scopes.count
    else { throw WalletFailure.core("invalid_access_catalog") }
    for preset in value.presets {
      guard preset.id.range(of: "^[a-z][a-z0-9-]{0,63}$", options: .regularExpression) != nil,
        !preset.name.isEmpty, preset.name.count <= 80, preset.version > 0,
        preset.version <= 9_007_199_254_740_991, preset.read_operations.count <= 5,
        Set(preset.read_operations).isSubset(of: ["list", "get", "relationships", "children", "blockers"]),
        Set(preset.read_operations).count == preset.read_operations.count,
        preset.write_operations.count <= 64,
        Set(preset.write_operations).count == preset.write_operations.count,
        preset.write_operations.allSatisfy({ $0.count <= 128 && $0.hasPrefix("devgraph.") })
      else { throw WalletFailure.core("invalid_access_catalog") }
    }
    for scope in value.scopes {
      try scope.resource_path.validate()
      guard scope.resource == scope.resource_path.path.last, scope.title.count <= 4096,
        scope.parent == (scope.resource_path.path.count > 1 ? scope.resource_path.path.dropLast().last : nil)
      else { throw WalletFailure.core("invalid_access_catalog") }
    }
    raw.removeValue(forKey: "scopes"); raw.removeValue(forKey: "scope_semantics")
    raw.removeValue(forKey: "catalog_digest_sha256")
    let canonical = try JSONSerialization.data(withJSONObject: raw, options: [.sortedKeys, .withoutEscapingSlashes])
    let digest = SHA256.hash(data: canonical).map { String(format: "%02x", $0) }.joined()
    guard digest == value.catalog_digest_sha256 else { throw WalletFailure.core("invalid_access_catalog") }
    return value
  }
}

public struct WorkAccessPreference: Codable, Sendable, Equatable {
  public let catalog_digest_sha256: String
  public let id: String?
  public let version: UInt64?
  public let resource_paths: [WorkResourcePath]?
  public init(catalog: WorkAccessCatalog, presetID: String?, paths: [WorkResourcePath]) throws {
    let preset = catalog.presets.first { $0.id == presetID }
    guard presetID == nil || preset != nil, paths.count <= 16, Set(paths).count == paths.count,
      paths.allSatisfy({ path in catalog.scopes.contains(where: { $0.resource_path == path }) })
    else { throw WalletFailure.core("invalid_access_preference") }
    for path in paths { try path.validate() }
    catalog_digest_sha256 = catalog.catalog_digest_sha256; id = preset?.id; version = preset?.version
    resource_paths = paths.isEmpty ? nil : paths
  }
  enum CodingKeys: String, CodingKey { case catalog_digest_sha256, id, version, resource_paths }
  public func encode(to encoder: Encoder) throws {
    var c = encoder.container(keyedBy: CodingKeys.self)
    try c.encode(catalog_digest_sha256, forKey: .catalog_digest_sha256)
    if let id { try c.encode(id, forKey: .id) } else { try c.encodeNil(forKey: .id) }
    if let version { try c.encode(version, forKey: .version) } else { try c.encodeNil(forKey: .version) }
    try c.encodeIfPresent(resource_paths, forKey: .resource_paths)
  }
}
public extension DevgraphReadClient {
  func accessCatalog() async throws -> WorkAccessCatalog {
    let request = URLRequest(url: try configuration.apiURL("/devgraph/access-requests/v2/catalog"))
    let data = try await transport.request(request, maximum: 262_144)
    return try WorkAccessCatalog.decode(data, receiver: configuration.authorityOrigin, issuer: configuration.issuer)
  }
}

/// Presentation-only path union; exact grants remain a server/operator decision.
public enum WorkScopeSelection {
  public static func covers(_ parent: WorkResourcePath, _ child: WorkResourcePath) -> Bool {
    parent.path.allSatisfy { child.path.contains($0) }
  }
  public static func normalized(_ paths: [WorkResourcePath]) throws -> [WorkResourcePath] {
    for path in paths { try path.validate() }
    var unique: [WorkResourcePath] = []
    for path in paths where !unique.contains(path) { unique.append(path) }
    let roots = unique.filter { path in !unique.contains { $0 != path && covers($0, path) } }
    guard roots.count <= 16 else { throw WalletFailure.core("too_many_resource_paths") }
    return roots
  }
  public static func label(_ path: WorkResourcePath, scopes: [WorkScopeOption]) -> String {
    path.path.map { anchor in
      guard let row = scopes.first(where: { $0.resource == anchor }) else { return anchor }
      return "\(row.kind): \(row.title)"
    }.joined(separator: " → ")
  }
  public static func tree(_ scopes: [WorkScopeOption]) -> [WorkScopeTreeNode] {
    let byPath = Dictionary(uniqueKeysWithValues: scopes.map { ($0.resource_path.path, $0.resource) })
    var grouped: [String: [WorkScopeOption]] = [:]
    for row in scopes {
      var parent = ""
      if row.resource_path.path.count > 1 {
        for length in stride(from: row.resource_path.path.count - 1, through: 1, by: -1) {
          if let found = byPath[Array(row.resource_path.path.prefix(length))] { parent = found; break }
        }
      }
      grouped[parent, default: []].append(row)
    }
    func children(_ identifier: String) -> [WorkScopeTreeNode] {
      (grouped[identifier] ?? [])
        .sorted { $0.title == $1.title ? $0.resource < $1.resource : $0.title < $1.title }
        .map { row in
          let nested = children(row.resource)
          return WorkScopeTreeNode(option: row, children: nested.isEmpty ? nil : nested)
        }
    }
    return children("")
  }
}
public struct WorkScopeTreeNode: Identifiable, Sendable {
  public let option: WorkScopeOption
  public let children: [WorkScopeTreeNode]?
  public var id: String { option.resource }
  public init(option: WorkScopeOption, children: [WorkScopeTreeNode]?) { self.option = option; self.children = children }
}
