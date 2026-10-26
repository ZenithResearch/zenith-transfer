import Foundation

/// Resource admission is separate from the Wallet's community membership.
/// Older services omit this disclosure; their existing proof behavior is retained.
public enum WorkMembershipRequirement: String, Sendable {
  case optional, required, unspecified

  public var disclosure: String {
    switch self {
    case .optional: return "Community membership is not required. No membership proof will be shared."
    case .required: return "This server requires community membership. Your Wallet will share its membership proof."
    case .unspecified: return "This server has not stated its membership requirement. Your Wallet will include any active membership proof."
    }
  }

  /// Only applies to membership-bearing consent envelopes, never signed read
  /// calls. Preserve the exact challenge and holder signature from Wallet Core.
  func approvalBody(_ data: Data) throws -> Data {
    guard self == .optional else { return data }
    guard var body = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(body.keys) == ["challenge", "signature", "proof"],
      body["challenge"] is [String: Any], body["signature"] is String,
      body["proof"] is [String: Any]
    else { throw WalletFailure.core("invalid_response") }
    body["proof"] = [String: String]()
    return try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys, .withoutEscapingSlashes])
  }
}

extension DevgraphReadClient {
  func membershipRequirement() async throws -> WorkMembershipRequirement {
    // Fixed-origin, credential-free metadata. This changes disclosure only;
    // it cannot change the issuer pin, grant scope or signature verification.
    let url = try configuration.apiURL("/monitor/wallet-access/v1")
    let data = try await transport.request(URLRequest(url: url), maximum: 65_536)
    guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      throw WalletFailure.core("invalid_response")
    }
    guard let raw = value["membership_requirement"] else { return .unspecified }
    guard let text = raw as? String, let requirement = WorkMembershipRequirement(rawValue: text),
      requirement != .unspecified else { throw WalletFailure.core("invalid_response") }
    return requirement
  }
}
