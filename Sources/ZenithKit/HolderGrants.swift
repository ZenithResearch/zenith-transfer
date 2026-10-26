import Foundation

public struct HolderIssuerPin: Codable, Sendable, Equatable {
  public let issuer: String
  public let key_id: String
  public let public_key: String
  public let service: String
  public init(issuer: String, keyID: String, publicKey: String, service: String) {
    self.issuer = issuer
    self.key_id = keyID
    self.public_key = publicKey
    self.service = service
  }
}
public struct HolderGrantNode: Codable, Sendable {
  public let kind: String
  public let id: String
}
public struct HolderGrantScope: Decodable, Sendable {
  public let mode: String
  public let roots: [[HolderGrantNode]]?
}
public struct HolderGrantPermission: Decodable, Sendable {
  public let operation: String
  public let resource: String
  public let scope: HolderGrantScope
  public let conditions: String
  enum CodingKeys: String, CodingKey { case operation, resource, scope, constraints }
  public init(from decoder: Decoder) throws {
    let c = try decoder.container(keyedBy: CodingKeys.self)
    operation = try c.decode(String.self, forKey: .operation)
    resource = try c.decode(String.self, forKey: .resource)
    scope = try c.decode(HolderGrantScope.self, forKey: .scope)
    let v = try c.decode(PublicJSON.self, forKey: .constraints)
    let e = JSONEncoder()
    e.outputFormatting = [.prettyPrinted, .sortedKeys]
    conditions = String(data: try e.encode(v), encoding: .utf8) ?? ""
  }
  public var title: String {
    [
      "devgraph.work.list": "List work", "devgraph.work.get": "Read work details",
      "devgraph.work.relationships": "Read work relationships",
      "devgraph.arena.list": "List arenas", "devgraph.arena.get": "Read arena details",
    ][operation] ?? operation
  }
}
public struct HolderGrantValidity: Decodable, Sendable {
  public let mode: String
  public let not_before: UInt64
  public let not_after: UInt64?
}
public struct HolderGrantSummary: Decodable, Sendable, Identifiable {
  public let service: String
  public let issuer: String
  public let grant_id: String
  public let holder_public_key: String
  public let revision: String
  public let validity: HolderGrantValidity
  public let permissions: [HolderGrantPermission]
  public let onward_delegation: Bool
  public let max_credential_lifetime_seconds: UInt64
  public var id: String { service + ":" + grant_id }
}
public struct HolderGrantReview: Sendable {
  public let grant: Data
  public let pin: HolderIssuerPin
  public let summary: HolderGrantSummary
  public let lifecycle: UInt64
  public init(grant: Data, pin: HolderIssuerPin, summary: HolderGrantSummary, lifecycle: UInt64) {
    self.grant = grant
    self.pin = pin
    self.summary = summary
    self.lifecycle = lifecycle
  }
}
