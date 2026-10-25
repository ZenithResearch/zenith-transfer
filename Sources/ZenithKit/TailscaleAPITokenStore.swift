#if os(macOS)
import Foundation
import Security

/// Public display metadata only. The token is never Codable or part of Wallet storage.
public struct TailscaleAPITokenProfile: Codable, Identifiable, Equatable {
  public let id: UUID
  public let name: String
  public let tailnet: String
  public let updated: Date
}

public enum TailscaleAPITokenStorageFailure: Error, LocalizedError {
  case invalidInput, unavailable, missing
  public var errorDescription: String? {
    switch self {
    case .invalidInput: return "Enter a label, a Tailnet name/ID (or - for the token’s default), and an API access token beginning with tskey-api-."
    case .unavailable: return "The Tailscale API token could not be accessed in this Mac’s Keychain. Check Keychain access and try again. No file fallback was used."
    case .missing: return "This saved API token is no longer available. Select another token or save a replacement in Network settings."
    }
  }
}

/// Application network secrets, independent of Castalia custody and Wallet backups.
/// Uses the macOS login Keychain for this ad-hoc signed preview, with the default
/// app ACL, no shared access group and synchronization disabled. Future signed
/// releases must qualify access across upgrades; never silently fall back to files.
public final class TailscaleAPITokenStore {
  struct Operations {
    var copy: ([String: Any]) -> (OSStatus, Any?)
    var add: ([String: Any]) -> OSStatus
    var update: ([String: Any], [String: Any]) -> OSStatus
    var delete: ([String: Any]) -> OSStatus
    static let system = Operations(copy: { query in
      var result: CFTypeRef?
      let status = SecItemCopyMatching(query as CFDictionary, &result)
      return (status, result)
    }, add: { SecItemAdd($0 as CFDictionary, nil) },
      update: { SecItemUpdate($0 as CFDictionary, $1 as CFDictionary) },
      delete: { SecItemDelete($0 as CFDictionary) })
  }
  private let operations: Operations
  private let service: String
  private static let serviceName = "ca.zenith.preview.transfer.tailscale-api.v1"
  public init() { operations = .system; service = Self.serviceName }
  init(operations: Operations, service: String = TailscaleAPITokenStore.serviceName) {
    self.operations = operations; self.service = service
  }
  private var base: [String: Any] {
    [kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrSynchronizable as String: false,
      kSecUseDataProtectionKeychain as String: false]
  }
  private func query(_ id: UUID) -> [String: Any] {
    var query = base; query[kSecAttrAccount as String] = id.uuidString; return query
  }
  public func profiles() throws -> [TailscaleAPITokenProfile] {
    var query = base
    query[kSecReturnAttributes as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitAll
    let (status, result) = operations.copy(query)
    if status == errSecItemNotFound { return [] }
    guard status == errSecSuccess, let rows = result as? [[String: Any]], rows.count <= 100
    else { throw TailscaleAPITokenStorageFailure.unavailable }
    let profiles = try rows.map { row -> TailscaleAPITokenProfile in
      guard let bytes = row[kSecAttrGeneric as String] as? Data, bytes.count <= 2048,
        let value = try? JSONDecoder().decode(TailscaleAPITokenProfile.self, from: bytes),
        value.id.uuidString == row[kSecAttrAccount as String] as? String,
        (try? Self.label(value.name)) == value.name,
        (try? TailscaleKeyCreator.validatedTailnet(value.tailnet)) == value.tailnet
      else { throw TailscaleAPITokenStorageFailure.unavailable }
      return value
    }
    guard Set(profiles.map(\.id)).count == profiles.count else { throw TailscaleAPITokenStorageFailure.unavailable }
    return profiles.sorted { $0.name == $1.name ? $0.id.uuidString < $1.id.uuidString : $0.name < $1.name }
  }
  @discardableResult public func save(name: String, tailnet: String, token: String,
    replacing: TailscaleAPITokenProfile? = nil) throws -> TailscaleAPITokenProfile {
    let validatedName: String, network: String, secret: String
    do {
      validatedName = try Self.label(name)
      network = try TailscaleKeyCreator.validatedTailnet(tailnet)
      secret = try TailscaleKeyCreator.validatedAPIToken(token)
    } catch { throw TailscaleAPITokenStorageFailure.invalidInput }
    let profile = TailscaleAPITokenProfile(id: replacing?.id ?? UUID(), name: validatedName, tailnet: network, updated: Date())
    let attributes: [String: Any] = [kSecAttrLabel as String: "Zenith Transfer · Tailscale · " + validatedName,
      kSecAttrGeneric as String: try JSONEncoder().encode(profile), kSecValueData as String: Data(secret.utf8)]
    let status: OSStatus
    if replacing != nil {
      status = operations.update(query(profile.id), attributes)
    } else {
      status = operations.add(base.merging(attributes) { _, new in new }.merging([kSecAttrAccount as String: profile.id.uuidString]) { _, new in new })
    }
    if status == errSecItemNotFound { throw TailscaleAPITokenStorageFailure.missing }
    guard status == errSecSuccess else { throw TailscaleAPITokenStorageFailure.unavailable }
    return profile
  }
  /// Called only after the user's final Generate action, never for listing or display.
  public func token(for profile: TailscaleAPITokenProfile) throws -> String {
    var query = query(profile.id)
    query[kSecReturnData as String] = true; query[kSecReturnAttributes as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    let (status, result) = operations.copy(query)
    if status == errSecItemNotFound { throw TailscaleAPITokenStorageFailure.missing }
    guard status == errSecSuccess, let row = result as? [String: Any],
      let metadata = row[kSecAttrGeneric as String] as? Data, metadata.count <= 2048,
      let current = try? JSONDecoder().decode(TailscaleAPITokenProfile.self, from: metadata), current == profile,
      let bytes = row[kSecValueData as String] as? Data, bytes.count <= 512,
      let raw = String(data: bytes, encoding: .utf8), let token = try? TailscaleKeyCreator.validatedAPIToken(raw)
    else { throw TailscaleAPITokenStorageFailure.unavailable }
    return token
  }
  /// Forgetting is local only; revocation remains an explicit Tailscale-console action.
  public func remove(_ profile: TailscaleAPITokenProfile) throws {
    let status = operations.delete(query(profile.id))
    guard status == errSecSuccess || status == errSecItemNotFound else { throw TailscaleAPITokenStorageFailure.unavailable }
  }
  private static func label(_ raw: String) throws -> String {
    let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    guard (1...80).contains(value.utf8.count), !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
    else { throw TailscaleAPITokenStorageFailure.invalidInput }
    return value
  }
}
#endif
