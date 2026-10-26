import CastaliaSignerProtocol
import CryptoKit
import Foundation
import Security
import LocalAuthentication

/// Signer-only, non-synchronizing Keychain records. No shared access group and
/// no main-app fallback. Release qualification must check the signed app's
/// application identifier and private Keychain entitlement before enabling it.
public final class SignerDeviceVault: @unchecked Sendable {
  private let service = "ca.zenith.castalia-signer.device.v1"
  private let lock = NSLock()
  public init() {}
  public enum Record: String { case journalKey, transportSigningKey, transportAgreementKey }
  public func journalKey() throws -> SymmetricKey { SymmetricKey(data: try readOrCreate(.journalKey)) }
  public func signingKey() throws -> Curve25519.Signing.PrivateKey {
    try Curve25519.Signing.PrivateKey(rawRepresentation: readOrCreate(.transportSigningKey))
  }
  public func agreementKey() throws -> Curve25519.KeyAgreement.PrivateKey {
    try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: readOrCreate(.transportAgreementKey))
  }
  private func query(_ record: Record) -> [String: Any] {
    [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
      kSecAttrAccount as String: record.rawValue, kSecAttrSynchronizable as String: false,
      kSecUseDataProtectionKeychain as String: true]
  }
  private func read(_ record: Record) throws -> Data? {
    var query = query(record); query[kSecReturnData as String] = true; query[kSecMatchLimit as String] = kSecMatchLimitOne
    // Never let a caller silently trigger a Keychain authentication dialog.
    let context = LAContext(); context.interactionNotAllowed = true
    query[kSecUseAuthenticationContext as String] = context
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess, let bytes = result as? Data, bytes.count == 32 else { throw SignerFailure.unavailable }
    return bytes
  }
  private func readOrCreate(_ record: Record) throws -> Data {
    lock.lock(); defer { lock.unlock() }
    if let existing = try read(record) { return existing }
    var bytes = Data(count: 32)
    let status = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
    guard status == errSecSuccess else { throw SignerFailure.unavailable }
    var values = query(record); values[kSecValueData as String] = bytes
    values[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    let added = SecItemAdd(values as CFDictionary, nil)
    if added == errSecDuplicateItem {
      bytes.resetBytes(in: 0..<bytes.count)
      guard let original = try read(record) else { throw SignerFailure.unavailable }; return original
    }
    guard added == errSecSuccess else { bytes.resetBytes(in: 0..<bytes.count); throw SignerFailure.unavailable }
    return bytes
  }
}
