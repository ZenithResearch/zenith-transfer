import Foundation

/// Complete verified disclosure; signing tokens never leave native custody.
public struct OperatorConsent: Decodable, Identifiable, Sendable {
  let token: String
  let summary: Summary
  let lifecycle: UInt64
  public var id: String { token }
  public var issuer: String { summary.issuer }
  public var receiver: String { summary.receiver }
  public var operation: String { summary.operation }
  public var expiresAt: Date { Date(timeIntervalSince1970: TimeInterval(summary.expires_at)) }
  public var details: Data { summary.details.data }
  struct Summary: Decodable, Sendable {
    let issuer: String
    let receiver: String
    let operation: String
    let expires_at: UInt64
    let native_protocol: String
    let details: PublicJSON
  }
  enum CodingKeys: String, CodingKey { case token, summary }
  public init(from decoder: Decoder) throws {
    let c = try decoder.container(keyedBy: CodingKeys.self)
    token = try c.decode(String.self, forKey: .token); summary = try c.decode(Summary.self, forKey: .summary)
    lifecycle = 0
  }
  init(token: String, summary: Summary, lifecycle: UInt64) {
    self.token = token; self.summary = summary; self.lifecycle = lifecycle
  }
}

/// Integer-only, portable public protocol JSON. No lossy floating point decode.
indirect enum PublicJSON: Codable, Sendable {
  case object([String: PublicJSON]), array([PublicJSON]), string(String), number(Int64), bool(Bool), null
  init(from decoder: Decoder) throws {
    let c = try decoder.singleValueContainer()
    if c.decodeNil() { self = .null }
    else if let x = try? c.decode(Bool.self) { self = .bool(x) }
    else if let x = try? c.decode(Int64.self), x >= -9_007_199_254_740_991 && x <= 9_007_199_254_740_991 { self = .number(x) }
    else if let x = try? c.decode(String.self) { self = .string(x) }
    else if let x = try? c.decode([String: PublicJSON].self) { self = .object(x) }
    else { self = .array(try c.decode([PublicJSON].self)) }
  }
  func encode(to encoder: Encoder) throws {
    var c = encoder.singleValueContainer()
    switch self {
    case .object(let x): try c.encode(x)
    case .array(let x): try c.encode(x)
    case .string(let x): try c.encode(x)
    case .number(let x): try c.encode(x)
    case .bool(let x): try c.encode(x)
    case .null: try c.encodeNil()
    }
  }
  var data: Data { (try? JSONEncoder().encode(self)) ?? Data() }
}
