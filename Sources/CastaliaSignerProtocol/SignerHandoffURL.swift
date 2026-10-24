import Foundation

/// URL routing is only a delivery mechanism. The sealed envelope, pinned peer
/// and signed inner message authenticate the request. No caller-chosen callback.
public enum SignerHandoffURL {
  private static let maximumURLBytes = 16_384
  public static func request(_ envelope: SignerSealedHandoff) throws -> URL {
    try url(envelope, scheme: "castalia-signer", host: "request")
  }
  public static func response(_ envelope: SignerSealedHandoff, clientScheme: String) throws -> URL {
    guard ["zenith-wallet-client", "zenith-transfer-client"].contains(clientScheme) else { throw SignerFailure.unpairedClient }
    return try url(envelope, scheme: clientScheme, host: "signer-result")
  }
  private static func url(_ envelope: SignerSealedHandoff, scheme: String, host: String) throws -> URL {
    guard (host == "request" && envelope.direction == .request) ||
      (host == "signer-result" && envelope.direction == .response) else { throw SignerFailure.invalidMessage }
    let payload = try envelope.encoded().base64EncodedString()
      .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
    var parts = URLComponents(); parts.scheme = scheme; parts.host = host
    parts.queryItems = [URLQueryItem(name: "message", value: payload)]
    guard let url = parts.url, url.absoluteString.utf8.count <= maximumURLBytes else { throw SignerFailure.invalidMessage }
    return url
  }
  public static func decode(_ url: URL, expectedScheme: String, direction: SignerHandoffDirection) throws -> SignerSealedHandoff {
    guard ["castalia-signer", "zenith-wallet-client", "zenith-transfer-client"].contains(expectedScheme),
      url.absoluteString.utf8.count <= maximumURLBytes,
      let parts = URLComponents(url: url, resolvingAgainstBaseURL: false), parts.scheme == expectedScheme,
      parts.host == (direction == .request ? "request" : "signer-result"), parts.path.isEmpty,
      parts.user == nil, parts.password == nil, parts.port == nil, parts.fragment == nil,
      let items = parts.queryItems, items.count == 1, items[0].name == "message",
      var value = items[0].value, !value.isEmpty,
      value.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95 }) else {
      throw SignerFailure.invalidMessage
    }
    value = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    value += String(repeating: "=", count: (4 - value.count % 4) % 4)
    guard let data = Data(base64Encoded: value) else { throw SignerFailure.invalidMessage }
    let envelope = try SignerSealedHandoff.decode(data)
    guard envelope.direction == direction else { throw SignerFailure.changedRequest }
    return envelope
  }
}
