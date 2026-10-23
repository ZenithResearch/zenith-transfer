import Foundation

public enum HermesChatError: LocalizedError, Equatable {
  case setup, authentication, unsupported, invalidResponse, uncertainDelivery, storage
  public var errorDescription: String? {
    switch self {
    case .storage: return "Could not save the chat connection. Unlock your iPhone and try again."
    case .setup: return "Choose your Hermes gateway and enter its connection key."
    case .authentication: return "The gateway key was not accepted. Check Chat connection settings."
    case .unsupported: return "This gateway needs the Hermes Sessions API enabled."
    case .invalidResponse: return "The gateway returned an unexpected response."
    case .uncertainDelivery:
      return
        "The reply was interrupted. Hermes may still be working. Refresh the conversation before sending again."
    }
  }
}

public struct HermesChatConnection: Codable, Sendable, Equatable {
  public let name: String
  public let receiver: URL
  public init(name: String, receiver: URL) throws {
    self.name = name.trimmingCharacters(in: .whitespacesAndNewlines)
    self.receiver = try WorkServerSettings.address(receiver.absoluteString)
    guard !self.name.isEmpty, self.name.count <= 80 else { throw HermesChatError.setup }
  }
  public func validate() throws { _ = try Self(name: name, receiver: receiver) }
  public static func validateKey(_ value: String) throws {
    guard (8...4096).contains(value.utf8.count), value.utf8.allSatisfy({ $0 > 32 && $0 < 127 })
    else {
      throw HermesChatError.setup
    }
  }
}

/// Installation-local state belongs in the OS Keychain, never Wallet exports.
/// No chat text or upstream model-provider credential is stored here.
public struct HermesChatSettings: Codable, Sendable {
  public let connection: HermesChatConnection
  public let key: String
  public var sessionID: String?
  public var awaitingReplyAfter: Int?
  public init(connection: HermesChatConnection, key: String) throws {
    try connection.validate()
    try HermesChatConnection.validateKey(key)
    self.connection = connection
    self.key = key
  }
  public static func importFile(_ data: Data) throws -> Self {
    guard data.count <= 8192,
      let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(raw.keys) == ["schema", "name", "receiver", "key"],
      raw["schema"] as? String == "zenith.hermes-chat.v1",
      let name = raw["name"] as? String, let address = raw["receiver"] as? String,
      let key = raw["key"] as? String
    else { throw HermesChatError.setup }
    return try Self(
      connection: HermesChatConnection(name: name, receiver: WorkServerSettings.address(address)),
      key: key)
  }
}

public struct HermesChatMessage: Identifiable, Sendable {
  public let id: String
  public let role: String
  public let text: String
  public init(id: String, role: String, text: String) {
    self.id = id
    self.role = role
    self.text = text
  }
}
public struct HermesChatHistory: Sendable {
  public let sessionID: String
  public let messages: [HermesChatMessage]
  public func hasReply(after baseline: Int) -> Bool {
    messages.count >= baseline + 2 && messages.last?.role == "assistant"
  }
}

public final class HermesChatClient: Sendable {
  let settings: HermesChatSettings
  let transport: PrivateTransport
  /// Transport must come from PrivateNetworkSession; there is no default route.
  public init(settings: HermesChatSettings, transport: PrivateTransport) throws {
    try settings.connection.validate()
    try HermesChatConnection.validateKey(settings.key)
    self.settings = settings
    self.transport = transport
  }
  public func cancel() { transport.cancel() }
  private func request(_ path: String, body: [String: Any]? = nil) async throws -> Data {
    var request = URLRequest(
      url: settings.connection.receiver.appendingPathComponent(path),
      timeoutInterval: path.hasSuffix("/chat") ? 300 : 20)
    request.setValue("Bearer " + settings.key, forHTTPHeaderField: "Authorization")
    if let body {
      request.httpMethod = "POST"
      request.setValue("application/json", forHTTPHeaderField: "Content-Type")
      request.httpBody = try JSONSerialization.data(withJSONObject: body)
    }
    do { return try await transport.request(request, maximum: 2_097_152) } catch let error
      as WalletFailure
    {
      if error == .core("access_denied") { throw HermesChatError.authentication }
      if error == .invalidFile { throw HermesChatError.invalidResponse }
      throw error
    }
  }
  public func check() async throws {
    struct Capabilities: Decodable {
      let object: String
      struct Features: Decodable { let session_chat: Bool? }
      struct Endpoint: Decodable {
        let method: String
        let path: String
      }
      let features: Features
      let endpoints: [String: Endpoint]
    }
    let capabilities = try JSONDecoder().decode(
      Capabilities.self, from: await request("v1/capabilities"))
    guard capabilities.object == "hermes.api_server.capabilities",
      capabilities.endpoints["session_create"]?.method == "POST",
      capabilities.endpoints["session_create"]?.path == "/api/sessions",
      capabilities.endpoints["session_messages"]?.method == "GET",
      capabilities.endpoints["session_messages"]?.path == "/api/sessions/{session_id}/messages",
      capabilities.features.session_chat == true
    else { throw HermesChatError.unsupported }
  }
  public func createSession(id: String) async throws {
    try validSession(id)
    struct Result: Decodable {
      struct Session: Decodable { let id: String }
      let session: Session
    }
    let response = try JSONDecoder().decode(
      Result.self, from: await request("api/sessions", body: ["id": id]))
    guard response.session.id == id else { throw HermesChatError.invalidResponse }
  }
  public func history(sessionID: String) async throws -> HermesChatHistory {
    try validSession(sessionID)
    struct Part: Decodable {
      let type: String
      let text: String?
    }
    struct Message: Decodable {
      let role: String
      let content: String
      let hasToolCalls: Bool
      enum CodingKeys: CodingKey { case role, content, tool_calls }
      init(from decoder: Decoder) throws {
        let v = try decoder.container(keyedBy: CodingKeys.self)
        role = try v.decode(String.self, forKey: .role)
        struct ToolCall: Decodable {}
        hasToolCalls = ((try? v.decode([ToolCall].self, forKey: .tool_calls))?.isEmpty == false)
        if let text = try? v.decode(String.self, forKey: .content) {
          content = text
        } else if let parts = try? v.decode([Part].self, forKey: .content) {
          content = parts.filter { ["text", "output_text", "input_text"].contains($0.type) }
            .compactMap(\.text).joined(separator: "\n")
        } else {
          content = ""
        }
      }
    }
    struct Result: Decodable {
      let session_id: String
      let data: [Message]
    }
    let result = try JSONDecoder().decode(
      Result.self, from: await request("api/sessions/" + sessionID + "/messages"))
    try validSession(result.session_id)
    guard result.data.count <= 2000 else { throw HermesChatError.invalidResponse }
    let messages = result.data.enumerated().compactMap { index, message -> HermesChatMessage? in
      guard ["user", "assistant"].contains(message.role), !message.content.isEmpty,
        !message.hasToolCalls
      else { return nil }
      return HermesChatMessage(
        id: result.session_id + ":" + String(index), role: message.role, text: message.content)
    }
    return HermesChatHistory(sessionID: result.session_id, messages: messages)
  }
  public func send(_ text: String, sessionID: String) async throws -> HermesChatMessage {
    try validSession(sessionID)
    guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, text.utf8.count <= 32_768
    else { throw HermesChatError.invalidResponse }
    struct Result: Decodable {
      struct Message: Decodable {
        let role: String
        let content: String
      }
      let session_id: String
      let message: Message
    }
    let result = try JSONDecoder().decode(
      Result.self, from: await request("api/sessions/" + sessionID + "/chat", body: ["input": text])
    )
    try validSession(result.session_id)
    guard result.message.role == "assistant", !result.message.content.isEmpty else {
      throw HermesChatError.invalidResponse
    }
    return HermesChatMessage(
      id: result.session_id + ":reply:" + UUID().uuidString, role: "assistant",
      text: result.message.content)
  }
  private func validSession(_ value: String) throws {
    guard value.range(of: "^[A-Za-z0-9_-]{1,256}$", options: .regularExpression) != nil else {
      throw HermesChatError.invalidResponse
    }
  }
}
