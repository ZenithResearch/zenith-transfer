import Foundation

/// A standing grant's time bounds, not its revocation state or credential expiry.
/// Existing server drafts retain their finite wire formats until explicitly upgraded.
public struct GrantValidity: Sendable, Equatable {
  public static let schema = "castalia.grant-validity.v1"
  private static let maximum: UInt64 = 9_007_199_254_740_991
  public let notBefore: UInt64
  public let notAfter: UInt64?

  private init(notBefore: UInt64, notAfter: UInt64?) throws {
    guard notBefore <= Self.maximum,
      notAfter.map({ $0 > notBefore && $0 <= Self.maximum }) ?? true
    else { throw WalletFailure.core("invalid_grant_validity") }
    self.notBefore = notBefore; self.notAfter = notAfter
  }
  public static func decode(_ data: Data) throws -> Self {
    var reader = ValidityObjectReader(data)
    let fields = try reader.read()
    guard fields["schema"] == .string(schema),
      case .integer(let start) = fields["not_before"]
    else { throw WalletFailure.core("invalid_grant_validity") }
    switch fields["mode"] {
    case .string("dated"):
      guard Set(fields.keys) == ["schema", "mode", "not_before", "not_after"],
        case .integer(let end) = fields["not_after"]
      else { throw WalletFailure.core("invalid_grant_validity") }
      return try Self(notBefore: start, notAfter: end)
    case .string("until_revoked"):
      guard Set(fields.keys) == ["schema", "mode", "not_before"]
      else { throw WalletFailure.core("invalid_grant_validity") }
      return try Self(notBefore: start, notAfter: nil)
    default: throw WalletFailure.core("invalid_grant_validity")
    }
  }
  public func contains(_ now: UInt64) -> Bool {
    now <= Self.maximum && now >= notBefore && (notAfter.map { now < $0 } ?? true)
  }
  public func contained(by parent: Self) -> Bool {
    notBefore >= parent.notBefore && (parent.notAfter.map { limit in
      notAfter.map { $0 <= limit } ?? false
    } ?? true)
  }
  public func credentialDeadline(now: UInt64, lifetime: UInt64) throws -> UInt64 {
    guard contains(now), (1...3600).contains(lifetime)
    else { throw WalletFailure.core("grant_inactive_or_invalid_lifetime") }
    let deadline = min(now + lifetime, notAfter ?? UInt64.max)
    guard deadline <= Self.maximum else { throw WalletFailure.core("invalid_grant_validity") }
    return deadline
  }
}

/// This wire object is flat and has only strings and unsigned integer tokens.
/// Decode keys before detecting duplicates, including escaped spellings. A normal
/// JSONDecoder alone collapses duplicate keys and accepts integral float tokens.
private struct ValidityObjectReader {
  enum Scalar: Equatable { case string(String), integer(UInt64) }
  let bytes: [UInt8]
  var cursor = 0
  init(_ data: Data) { bytes = Array(data) }
  mutating func whitespace() {
    while cursor < bytes.count && [9, 10, 13, 32].contains(bytes[cursor]) { cursor += 1 }
  }
  mutating func take(_ byte: UInt8) throws {
    whitespace()
    guard cursor < bytes.count, bytes[cursor] == byte else { throw invalid() }
    cursor += 1
  }
  func invalid() -> WalletFailure { .core("invalid_grant_validity") }
  mutating func string() throws -> String {
    whitespace()
    let start = cursor
    try take(34)
    var escaped = false
    while cursor < bytes.count {
      let byte = bytes[cursor]; cursor += 1
      if escaped { escaped = false; continue }
      if byte == 92 { escaped = true; continue }
      if byte == 34 {
        return try JSONDecoder().decode(String.self, from: Data(bytes[start..<cursor]))
      }
    }
    throw invalid()
  }
  mutating func scalar() throws -> Scalar {
    whitespace()
    guard cursor < bytes.count else { throw invalid() }
    if bytes[cursor] == 34 { return .string(try string()) }
    let start = cursor
    while cursor < bytes.count && (48...57).contains(bytes[cursor]) { cursor += 1 }
    guard cursor > start, cursor - start == 1 || bytes[start] != 48,
      let value = UInt64(String(decoding: bytes[start..<cursor], as: UTF8.self))
    else { throw invalid() }
    return .integer(value)
  }
  mutating func read() throws -> [String: Scalar] {
    guard bytes.count <= 1024 else { throw invalid() }
    try take(123)
    var result: [String: Scalar] = [:]
    while true {
      let key = try string()
      guard result[key] == nil, result.count < 4 else { throw invalid() }
      try take(58)
      result[key] = try scalar()
      whitespace()
      guard cursor < bytes.count else { throw invalid() }
      if bytes[cursor] == 125 { cursor += 1; break }
      try take(44)
    }
    whitespace()
    guard cursor == bytes.count else { throw invalid() }
    return result
  }
}
