import Foundation

/// Process-lifetime application access, deliberately outside Wallet backup.
/// Restoring a journal cannot recreate a key or resume a session after app exit.
public actor HolderSessionRegistry {
  public static let shared = HolderSessionRegistry()
  private struct Entry: Sendable {
    let model: HolderSessionReviewModel, client: String, pin: HolderIssuerPin
    let challenge: HolderSessionChallenge, handle: String
  }
  private var entries: [String: Entry] = [:]
  public func retain(_ model: HolderSessionReviewModel, client: String, pin: HolderIssuerPin) async throws {
    guard let challenge = await model.challenge, let handle = await model.credentialHandle,
      await model.phase == .issued, challenge.intent.parent.pin == pin else { throw HolderSessionError.changed }
    entries[pin.service] = Entry(model: model, client: client, pin: pin, challenge: challenge, handle: handle)
  }
  public func review(configuration: WorkAccessConfiguration) async -> HolderSessionReviewModel? {
    guard let entry = matching(configuration), [.issued, .dispatched, .outcomeUnknown].contains(await entry.model.phase) else { return nil }
    return entry.model
  }
  public func challenge(configuration: WorkAccessConfiguration) async throws -> HolderSessionChallenge? {
    guard let entry = matching(configuration) else { return nil }
    guard await entry.model.phase == .issued, UInt64(Date().timeIntervalSince1970) < entry.challenge.expiresAt else { throw HolderSessionError.expired }
    return entry.challenge
  }
  public func execute(configuration: WorkAccessConfiguration, call: Data) async throws -> Data? {
    guard let entry = matching(configuration) else { return nil }
    // A retained session denies on expiry/revocation. Never silently fall back
    // to a root Wallet signature or create another approval on a read path.
    return try await entry.model.execute(client: entry.client, handle: entry.handle, call: call)
  }
  public func close(configuration: WorkAccessConfiguration) async {
    guard let entry = matching(configuration) else { return }
    entries.removeValue(forKey: entry.pin.service); await entry.model.close()
  }
  public func closeAll() async {
    let previous = Array(entries.values); entries.removeAll()
    for value in previous { await value.model.close() }
  }
  private func matching(_ c: WorkAccessConfiguration) -> Entry? {
    guard let service = c.serviceID, let entry = entries[service], entry.pin.issuer == c.issuer,
      entry.pin.key_id == c.authority.key_id, entry.pin.public_key == c.authority.public_key else { return nil }
    return entry
  }
}
