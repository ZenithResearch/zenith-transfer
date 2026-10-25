import Foundation

public enum TailscaleKeyCreationFailure: Error, LocalizedError, Equatable {
  case invalidInput, rejected, outcomeUnknown
  public var errorDescription: String? {
    switch self {
    case .invalidInput: return "Enter a Tailnet name or ID, a description, a 1–90 day enrollment window, and a Tailscale API access token beginning with tskey-api-. An enrollment auth key cannot create other keys."
    case .rejected: return "Tailscale rejected key creation. Check the Tailnet and the API token’s permissions or expiry. No automatic retry was sent."
    case .outcomeUnknown: return "Key creation could not be confirmed. A key may already exist. Check Tailscale’s Keys page before generating another; no automatic retry was sent."
    }
  }
}

/// Transient result, never a Wallet record or an automatically saved key file.
public struct GeneratedTailscaleAuthKey: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
  public let id: String
  public let secret: String
  public let expires: Date
  public var description: String { "GeneratedTailscaleAuthKey(<redacted>)" }
  public var debugDescription: String { description }
}

/// Only creates one-off, persistent-node auth keys on the official control plane.
/// No tags, preapproval, token persistence, OAuth-client creation or host changes.
public final class TailscaleKeyCreator: @unchecked Sendable {
  typealias Exchange = @Sendable (URLRequest) async throws -> PrivateHTTPResponse
  private let exchange: Exchange
  private let transport: PrivateTransport?
  public init(transport: PrivateTransport = PrivateTransport()) {
    self.transport = transport
    exchange = { try await transport.exchange($0, maximum: 65_536) }
  }
  init(exchange: @escaping Exchange) { self.exchange = exchange; transport = nil }
  public func cancel() { transport?.cancel() }

  public func generate(tailnet: String, description: String, expiryDays: Int,
    apiToken: String, now: Date = Date()) async throws -> GeneratedTailscaleAuthKey {
    try Task.checkCancellation()
    let tailnet = tailnet.trimmingCharacters(in: .whitespacesAndNewlines)
    let description = description.trimmingCharacters(in: .whitespacesAndNewlines)
    let token = apiToken.trimmingCharacters(in: .whitespacesAndNewlines)
    let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.@")
    let tokenCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
    guard (1...253).contains(tailnet.utf8.count), !tailnet.contains(".."),
      tailnet.unicodeScalars.allSatisfy({ allowed.contains($0) }), tailnet != ".",
      (1...100).contains(description.utf8.count),
      !description.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
      (1...90).contains(expiryDays), token.hasPrefix("tskey-api-"),
      (32...512).contains(token.utf8.count), token.unicodeScalars.allSatisfy({ tokenCharacters.contains($0) })
    else { throw TailscaleKeyCreationFailure.invalidInput }
    let seconds = expiryDays * 86_400
    let url = URL(string: "https://api.tailscale.com/api/v2/tailnet")!
      .appendingPathComponent(tailnet).appendingPathComponent("keys")
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("Basic " + Data((token + ":").utf8).base64EncodedString(), forHTTPHeaderField: "Authorization")
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue("application/json", forHTTPHeaderField: "Accept")
    request.httpBody = try JSONSerialization.data(withJSONObject: [
      "capabilities": ["devices": ["create": ["reusable": false, "ephemeral": false, "preauthorized": false, "tags": [String]()]]],
      "expirySeconds": seconds, "description": description
    ])
    try Task.checkCancellation()
    let response: PrivateHTTPResponse
    do { response = try await exchange(request) }
    catch { throw TailscaleKeyCreationFailure.outcomeUnknown }
    if [400, 401, 403, 404, 422].contains(response.status) { throw TailscaleKeyCreationFailure.rejected }
    guard (200..<300).contains(response.status) else { throw TailscaleKeyCreationFailure.outcomeUnknown }
    do {
      try Task.checkCancellation()
      var strict = OwnerPlanJSON(response.data, maximumBytes: 65_536, maximumKeys: 64, maximumArray: 64, maximumDepth: 8)
      try strict.validate()
      let object = try JSONSerialization.jsonObject(with: response.data) as? [String: Any]
      guard let capabilities = object?["capabilities"] as? [String: Any], Set(capabilities.keys) == ["devices"],
        let devices = capabilities["devices"] as? [String: Any], Set(devices.keys) == ["create"],
        let create = devices["create"] as? [String: Any],
        Set(create.keys).isSubset(of: ["reusable", "ephemeral", "preauthorized", "tags"])
      else { throw TailscaleKeyCreationFailure.outcomeUnknown }
      let value = try JSONDecoder().decode(Response.self, from: response.data)
      let grant = value.capabilities.devices.create
      guard !grant.reusable, !grant.ephemeral, !grant.preauthorized, grant.tags?.isEmpty != false,
        value.keyType == nil || value.keyType == "auth", value.invalid != true,
        value.scopes?.isEmpty != false, value.tags?.isEmpty != false,
        (1...128).contains(value.id.utf8.count),
        value.id.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }),
        let created = Self.date(value.created), let expires = Self.date(value.expires),
        created >= now.addingTimeInterval(-300), created <= now.addingTimeInterval(60),
        expires > max(now, created), expires <= now.addingTimeInterval(Double(seconds) + 60)
      else { throw TailscaleKeyCreationFailure.outcomeUnknown }
      let key = try TailscaleEnrollment.validatedKey(value.key)
      return GeneratedTailscaleAuthKey(id: value.id, secret: key, expires: expires)
    } catch { throw TailscaleKeyCreationFailure.outcomeUnknown }
  }
  private static func date(_ value: String) -> Date? {
    let format = ISO8601DateFormatter()
    if let date = format.date(from: value) { return date }
    format.formatOptions.insert(.withFractionalSeconds)
    return format.date(from: value)
  }
  private struct Response: Decodable {
    let id: String, key: String, created: String, expires: String
    let keyType: String?
    let invalid: Bool?
    let scopes: [String]?
    let tags: [String]?
    let capabilities: Capabilities
    struct Capabilities: Decodable {
      let devices: Devices
      struct Devices: Decodable {
        let create: Grant
        struct Grant: Decodable { let reusable: Bool, ephemeral: Bool, preauthorized: Bool; let tags: [String]? }
      }
    }
  }
}
