import Foundation

public enum WalletIdentityError: LocalizedError {
  case invalid, conflict, ownerChanged
  public var errorDescription: String? {
    switch self {
    case .invalid: return "Check the public identity fields. Do not enter passwords, tokens, private keys or session data."
    case .conflict: return "An identity conflicts with a saved record. Nothing was overwritten; review the records separately."
    case .ownerChanged: return "These records belong to a different Wallet. Unlock the original Wallet before continuing."
    }
  }
}
public enum WalletIdentityKind: String, Codable, CaseIterable, Identifiable, Sendable {
  case matrix, nostr, github, x
  public var id: String { rawValue }
  public var title: String { switch self { case .matrix: return "Matrix"; case .nostr: return "Nostr"; case .github: return "GitHub"; case .x: return "X" } }
}
private struct IdentityCodingKey: CodingKey {
  let stringValue: String
  let intValue: Int? = nil
  init?(stringValue: String) { self.stringValue = stringValue }
  init?(intValue: Int) { return nil }
}
private func identityKeys(_ decoder: Decoder, _ expected: Set<String>) throws {
  let keys = try decoder.container(keyedBy: IdentityCodingKey.self)
  guard Set(keys.allKeys.map(\.stringValue)) == expected else { throw WalletIdentityError.invalid }
}
private func publicIdentityText(_ text: String, maximum: Int, nonempty: Bool = false) -> Bool {
  let bidi: Set<UInt32> = [0x061c,0x200e,0x200f,0x202a,0x202b,0x202c,0x202d,0x202e,0x2066,0x2067,0x2068,0x2069]
  return (!nonempty || !text.isEmpty) && text.utf8.count <= maximum && !text.unicodeScalars.contains {
    $0.value < 32 || (0x7f...0x9f).contains($0.value) || bidi.contains($0.value)
  }
}
private func identityMatches(_ text: String, _ pattern: String) -> Bool { text.range(of: pattern, options: .regularExpression) != nil }

/// A public descriptor, not proof of account control or an authenticated session.
public struct WalletIdentity: Codable, Equatable, Identifiable, Sendable {
  public let accountId: String
  public let kind: WalletIdentityKind
  public let label: String
  public let identifier: String
  public let server: String
  public var id: String { accountId }
  enum CodingKeys: String, CodingKey { case accountId, kind, label, identifier, server }
  public init(accountId: String = UUID().uuidString.lowercased(), kind: WalletIdentityKind, label: String, identifier: String, server: String) throws {
    self.accountId = accountId; self.kind = kind; self.label = label; self.identifier = identifier; self.server = server
    try validate()
  }
  public init(from decoder: Decoder) throws {
    try identityKeys(decoder, ["accountId","kind","label","identifier","server"])
    let c = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(accountId: c.decode(String.self, forKey: .accountId), kind: c.decode(WalletIdentityKind.self, forKey: .kind), label: c.decode(String.self, forKey: .label), identifier: c.decode(String.self, forKey: .identifier), server: c.decode(String.self, forKey: .server))
  }
  public func validate() throws {
    guard let uuid = UUID(uuidString: accountId), uuid.uuidString.lowercased() == accountId,
      accountId != "00000000-0000-0000-0000-000000000000",
      publicIdentityText(label, maximum: 100, nonempty: true), publicIdentityText(identifier, maximum: 320, nonempty: true), publicIdentityText(server, maximum: 500)
    else { throw WalletIdentityError.invalid }
    func endpoint(_ scheme: String, originOnly: Bool) -> Bool {
      guard !server.contains("\\"), let delimiter = server.range(of: "://"),
        !server[delimiter.upperBound...].prefix(while: { $0 != "/" && $0 != "?" && $0 != "#" }).contains("@"),
        let url = URLComponents(string: server), url.scheme?.lowercased() == scheme, url.url != nil,
        let host = url.host, !host.isEmpty, !host.contains(where: { $0.isWhitespace }),
        url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
        url.port.map({ (1...65535).contains($0) }) ?? true else { return false }
      return !originOnly || url.path.isEmpty || url.path == "/"
    }
    switch kind {
    case .matrix:
      guard identityMatches(identifier, "^@[^\\s:@/]+:[a-zA-Z0-9.-]+(?::[0-9]{1,5})?$"), endpoint("https", originOnly: true) else { throw WalletIdentityError.invalid }
      if let port = identifier.split(separator: ":").dropFirst(2).first {
        guard let value = UInt16(port), value > 0 else { throw WalletIdentityError.invalid }
      }
    case .nostr:
      guard identityMatches(identifier, "^[a-f0-9]{64}$"), server.isEmpty || endpoint("wss", originOnly: false) else { throw WalletIdentityError.invalid }
    case .github, .x:
      guard identityMatches(identifier, "^[1-9][0-9]{0,39}$"), server.isEmpty else { throw WalletIdentityError.invalid }
    }
  }
}

public struct WalletIdentitySection: Codable, Equatable, Sendable {
  public let schema: String
  public let version: Int
  public let ownerMemberKey: String
  public let authority: String
  public let accounts: [WalletIdentity]
  enum CodingKeys: String, CodingKey { case schema, version, ownerMemberKey, authority, accounts }
  public init(ownerMemberKey: String, accounts: [WalletIdentity]) throws {
    schema = "castalia.wallet-identities.v1"; version = 1; authority = "descriptor-only"
    self.ownerMemberKey = ownerMemberKey; self.accounts = accounts.sorted { $0.accountId < $1.accountId }
    try validate()
  }
  public init(from decoder: Decoder) throws {
    try identityKeys(decoder, ["schema","version","ownerMemberKey","authority","accounts"])
    let c = try decoder.container(keyedBy: CodingKeys.self)
    guard try c.decode(String.self, forKey: .schema) == "castalia.wallet-identities.v1",
      try c.decode(Int.self, forKey: .version) == 1, try c.decode(String.self, forKey: .authority) == "descriptor-only" else { throw WalletIdentityError.invalid }
    try self.init(ownerMemberKey: c.decode(String.self, forKey: .ownerMemberKey), accounts: c.decode([WalletIdentity].self, forKey: .accounts))
  }
  public func validate() throws {
    guard identityMatches(ownerMemberKey, "^[a-f0-9]{64}$"), accounts.count <= 100 else { throw WalletIdentityError.invalid }
    var ids = Set<String>(), subjects = Set<String>()
    for account in accounts {
      try account.validate()
      guard ids.insert(account.accountId).inserted, subjects.insert(account.kind.rawValue + ":" + account.identifier).inserted else { throw WalletIdentityError.conflict }
    }
  }
  public static func decode(_ data: Data) throws -> Self {
    var reader = AccountRecordJSON(data, maximumBytes: 1_048_576, maximumKeys: 20, maximumArray: 100, maximumDepth: 8)
    try reader.validate()
    return try JSONDecoder().decode(Self.self, from: data)
  }
}

/// Pure preview builder. Never saves or removes a legacy registry file.
public struct WalletIdentityMigration: Sendable {
  public let proposed: WalletIdentitySection
  public let added: [WalletIdentity]
  public let applicationOnlyCount: Int
  public static func prepare(existing: WalletIdentitySection, legacy: [IdentityAccount]) throws -> Self {
    try existing.validate()
    var accounts = existing.accounts, added: [WalletIdentity] = [], applicationOnlyCount = 0
    for record in legacy {
      try record.validate()
      guard record.walletPublicKey == existing.ownerMemberKey else { throw WalletIdentityError.ownerChanged }
      if record.provider == .tailscale { applicationOnlyCount += 1; continue }
      let kind: WalletIdentityKind = record.provider == .matrix ? .matrix : .nostr
      let value = try WalletIdentity(accountId: record.id.uuidString.lowercased(), kind: kind, label: record.label, identifier: record.identifier, server: record.server)
      if let old = accounts.first(where: { $0.accountId == value.accountId }) {
        guard old == value else { throw WalletIdentityError.conflict }
        continue
      }
      guard !accounts.contains(where: { $0.kind == value.kind && $0.identifier == value.identifier }) else { throw WalletIdentityError.conflict }
      accounts.append(value); added.append(value)
    }
    return Self(proposed: try WalletIdentitySection(ownerMemberKey: existing.ownerMemberKey, accounts: accounts), added: added.sorted { $0.accountId < $1.accountId }, applicationOnlyCount: applicationOnlyCount)
  }
}

public struct WalletIdentitySnapshot: Sendable {
  public let section: WalletIdentitySection
  public let revision: UInt64
  public let chainAccounts: PublicAccounts?
  package init(section: WalletIdentitySection, revision: UInt64, chainAccounts: PublicAccounts?) {
    self.section = section; self.revision = revision; self.chainAccounts = chainAccounts
  }
}
