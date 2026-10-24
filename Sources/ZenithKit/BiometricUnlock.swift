import Foundation

/// One automatic Touch ID prompt per app launch. Cancellation, failure and a
/// deliberate manual lock must never cause an automatic prompt loop.
public struct AutomaticBiometricUnlock: Sendable {
  private var consumed = false
  public init() {}
  public mutating func claim(isPad: Bool, touchID: Bool, enabled: Bool, ready: Bool) -> Bool {
    guard !consumed, isPad, touchID, enabled, ready else { return false }
    consumed = true
    return true
  }
  public mutating func suppress() { consumed = true }
}

public enum BiometricUnlockError: LocalizedError {
  case unavailable, cancelled, missing, storage
  public var errorDescription: String? {
    switch self {
    case .unavailable: return "Biometric unlock is unavailable. Use your wallet password."
    case .cancelled: return "Unlock cancelled. You can try again or use your wallet password."
    case .missing: return "Set up biometric unlock again using your wallet password. Your wallet is unchanged."
    case .storage: return "Could not save biometric unlock. You can still use your wallet password."
    }
  }
}

public struct BiometricCredential: Codable, Sendable {
  public let identity: String
  public let password: String
  public init(identity: String, password: String) { self.identity = identity; self.password = password }
}

/// Only the OS adapter stores secrets. Test doubles never qualify device custody.
@MainActor public protocol BiometricCredentialStore {
  var isEnabled: Bool { get }
  func save(_ credential: BiometricCredential) async throws
  func read() async throws -> BiometricCredential
  func remove() throws
  func cancel()
}

@MainActor public final class BiometricUnlock {
  private let store: any BiometricCredentialStore
  public var isEnabled: Bool { store.isEnabled }
  public init(store: any BiometricCredentialStore) { self.store = store }

  public func enable(password: String, repository: any WalletSession) async throws -> WalletState {
    let ticket = repository.lifecycleTicket()
    // The existing Rust core validates the password before anything is saved.
    let state = try await repository.unlock(password: password, expectedLifecycle: ticket)
    guard let identity = state.publicKey else { throw WalletFailure.locked }
    do {
      try repository.checkLifecycle(ticket)
      try await store.save(BiometricCredential(identity: identity, password: password))
      try Task.checkCancellation()
      try repository.checkLifecycle(ticket)
      return state
    } catch {
      try? store.remove()
      await repository.lock()
      throw error
    }
  }

  public func unlock(repository: any WalletSession) async throws -> WalletState {
    let ticket = repository.lifecycleTicket()
    let credential = try await store.read()
    try Task.checkCancellation()
    try repository.checkLifecycle(ticket)
    return try await repository.unlock(password: credential.password, expectedLifecycle: ticket,
      expectedIdentity: credential.identity)
  }
  public func disable() throws { store.cancel(); try store.remove() }
  public func cancel() { store.cancel() }
}
