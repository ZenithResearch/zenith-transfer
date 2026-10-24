import Foundation

/// Common native Wallet information architecture. A destination is navigation,
/// never an authorization or a grant of access.
public enum WalletDestination: String, CaseIterable, Identifiable, Hashable, Sendable {
  case identities, membership, recovery, access, security, about
  /// Only destinations with an implemented portable backup belong in Wallet.
  /// Application-only screens remain addressable for Settings navigation.
  public var backupCoverage: WalletBackupCoverage? {
    switch self {
    case .identities: return .recoveryAndCastaway
    case .recovery: return .recovery
    case .membership: return .castaway
    case .access, .security, .about: return nil
    }
  }
  public static var walletCases: [Self] { allCases.filter { $0.backupCoverage != nil } }
  public var id: String { rawValue }
  public var title: String {
    switch self {
    case .identities: return "Identities & accounts"
    case .membership: return "Membership"
    case .recovery: return "Recovery"
    case .access: return "Credentials & access"
    case .security: return "Unlock & security"
    case .about: return "How Wallet works"
    }
  }
  public var symbol: String {
    switch self {
    case .identities: return "person.crop.circle"
    case .membership: return "person.crop.circle.badge.checkmark"
    case .recovery: return "doc.badge.arrow.up"
    case .access: return "key.horizontal"
    case .security: return "lock.shield"
    case .about: return "info.circle"
    }
  }
}

/// A storage location alone is not a backup promise. These are implemented
/// export/restore paths; full installation database backup is not yet exposed.
public enum WalletBackupCoverage: String, Sendable { case recovery, castaway, recoveryAndCastaway }

/// Mirrors Rust's scalar minimum and UTF-8 ceiling without changing a password.
public enum WalletPasswordRules {
  public static func permitsLocal(_ value: String) -> Bool {
    value.unicodeScalars.count >= 12 && value.utf8.count <= 4096
  }
  public static func importPassword(file: String, local: String, confirmation: String, reuse: Bool) -> String? {
    let selected = reuse ? file : local
    guard !file.isEmpty, permitsLocal(selected), reuse || local == confirmation else { return nil }
    return selected
  }
}

public enum WalletUnlockDuration: Int, CaseIterable, Identifiable, Sendable {
  case twoMinutes = 120, fiveMinutes = 300, fifteenMinutes = 900, thirtyMinutes = 1800
  case oneHour = 3600, fourHours = 14400, untilLocked = 0
  public var id: Int { rawValue }
  public static let selectableCases: [Self] = [.fifteenMinutes, .oneHour, .fourHours, .untilLocked]
  public var label: String {
    switch self {
    case .twoMinutes: return "2 minutes"
    case .fiveMinutes: return "5 minutes"
    case .fifteenMinutes: return "15 minutes"
    case .thirtyMinutes: return "30 minutes"
    case .oneHour: return "1 hour"
    case .fourHours: return "4 hours"
    case .untilLocked: return "Until I lock or quit"
    }
  }
  public static func load(_ defaults: UserDefaults, key: String) -> Self {
    guard let raw = defaults.object(forKey: key) as? Int, let value = Self(rawValue: raw) else { return .oneHour }
    return value
  }
}

/// Only explicit foreground user input resets inactivity. State reads, timers,
/// network refresh and activation do not. Sleep counts and rollback cannot extend it.
public struct WalletUnlockTimer {
  public private(set) var started: Date?
  public private(set) var lastActivity: Date?
  private var uptime: TimeInterval?
  public init() {}
  public mutating func observe(unlocked: Bool, now: Date, uptime: TimeInterval) {
    if !unlocked { clear() }
    else if started == nil { started = now; lastActivity = now; self.uptime = uptime }
  }
  public mutating func clear() { started = nil; lastActivity = nil; uptime = nil }
  /// Expired custody cannot be revived by the click that returns to the app.
  @discardableResult public mutating func activity(_ policy: WalletUnlockDuration, now: Date, uptime: TimeInterval) -> Bool {
    guard started != nil, !expired(policy, now: now, uptime: uptime) else { return false }
    lastActivity = now; self.uptime = uptime; return true
  }
  public func expired(_ policy: WalletUnlockDuration, now: Date, uptime: TimeInterval) -> Bool {
    guard policy != .untilLocked, let lastActivity, let initial = self.uptime else { return false }
    return max(now.timeIntervalSince(lastActivity), uptime - initial) >= Double(policy.rawValue)
  }
  public func deadline(_ policy: WalletUnlockDuration) -> Date? {
    guard policy != .untilLocked else { return nil }
    return lastActivity?.addingTimeInterval(Double(policy.rawValue))
  }
}
