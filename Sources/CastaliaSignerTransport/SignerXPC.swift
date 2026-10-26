#if os(macOS)
import CastaliaSignerProtocol
import Foundation
import Security

/// Production peers require stable Apple-issued signing, the exact Team and
/// bundle identifier. Ad-hoc development signatures do not satisfy this policy.
public struct SignerCodeIdentity: Equatable, Sendable {
  public let team: String
  public let bundle: String
  public init(team: String, bundle: String) throws {
    guard team.utf8.count == 10, team.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) }),
      (3...128).contains(bundle.utf8.count), bundle.contains("."),
      bundle.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 46 }),
      !bundle.hasPrefix("."), !bundle.hasSuffix("."), !bundle.contains("..") else { throw SignerFailure.unpairedClient }
    self.team = team; self.bundle = bundle
    var compiled: SecRequirement?
    guard SecRequirementCreateWithString(requirement as CFString, SecCSFlags(), &compiled) == errSecSuccess else {
      throw SignerFailure.unpairedClient
    }
  }
  public var requirement: String {
    "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\" and identifier \"\(bundle)\""
  }
}

/// Only the bounded message exchange is exported. Approval tickets, passwords,
/// the native core and storage are never Objective-C/XPC methods.
@objc public protocol CastaliaSignerXPC {
  func exchange(_ message: Data, reply: @escaping (Data?, String?) -> Void)
}

private final class XPCReply: @unchecked Sendable {
  private let lock = NSLock()
  private var continuation: CheckedContinuation<Data, Error>?
  init(_ continuation: CheckedContinuation<Data, Error>) { self.continuation = continuation }
  func finish(_ result: Result<Data, Error>) {
    lock.lock(); let pending = continuation; continuation = nil; lock.unlock()
    pending?.resume(with: result)
  }
}

public final class SignerXPCClient: SignerTransport, @unchecked Sendable {
  public static let serviceName = "ca.zenith.castalia-signer"
  private let identity: SignerCodeIdentity
  private let endpoint: NSXPCListenerEndpoint?
  public init(signer: SignerCodeIdentity) { identity = signer; endpoint = nil }
  /// Used with a signer-provided bootstrap endpoint, never an application's
  /// selected URL. The same OS peer requirement still applies.
  public init(endpoint: NSXPCListenerEndpoint, signer: SignerCodeIdentity) {
    self.endpoint = endpoint; identity = signer
  }
  public func exchange(_ message: Data) async throws -> Data {
    guard message.count <= 1_048_576 else { throw SignerFailure.invalidMessage }
    try Task.checkCancellation()
    let connection = endpoint.map { NSXPCConnection(listenerEndpoint: $0) }
      ?? NSXPCConnection(machServiceName: Self.serviceName)
    // Foundation enforces the requirement for every incoming message, including
    // after a peer exec. PID lookup is not used as a substitute for audit identity.
    connection.setCodeSigningRequirement(identity.requirement)
    connection.remoteObjectInterface = NSXPCInterface(with: CastaliaSignerXPC.self)
    defer { connection.invalidate() }
    return try await withCheckedThrowingContinuation { continuation in
      let completion = XPCReply(continuation)
      connection.invalidationHandler = { completion.finish(.failure(SignerFailure.unavailable)) }
      connection.interruptionHandler = { completion.finish(.failure(SignerFailure.unavailable)) }
      connection.activate()
      let proxy = connection.remoteObjectProxyWithErrorHandler { _ in completion.finish(.failure(SignerFailure.unavailable)) }
      guard let signer = proxy as? CastaliaSignerXPC else { completion.finish(.failure(SignerFailure.unavailable)); return }
      signer.exchange(message) { data, code in
        guard code == nil, let data, data.count <= 1_048_576 else {
          completion.finish(.failure(code.flatMap(SignerFailure.init(rawValue:)) ?? .unavailable)); return
        }
        completion.finish(.success(data))
      }
      DispatchQueue.global().asyncAfter(deadline: .now() + 15) { completion.finish(.failure(SignerFailure.unavailable)) }
    }
  }
}

private final class SignerXPCExport: NSObject, CastaliaSignerXPC {
  private let handler: @Sendable (Data) async throws -> Data
  private let lock = NSLock()
  private var active = false
  init(handler: @escaping @Sendable (Data) async throws -> Data) { self.handler = handler }
  func exchange(_ message: Data, reply: @escaping (Data?, String?) -> Void) {
    lock.lock()
    guard !active, message.count <= 1_048_576 else { lock.unlock(); reply(nil, SignerFailure.unavailable.rawValue); return }
    active = true; lock.unlock()
    Task {
      do {
        let now = UInt64(Date().timeIntervalSince1970)
        _ = try SignedSignerRequest.decode(message, now: now)
        let data = try await handler(message)
        guard data.count <= 1_048_576 else { throw SignerFailure.invalidMessage }
        reply(data, nil)
      } catch { reply(nil, (error as? SignerFailure ?? .unavailable).rawValue) }
      clearActive()
    }
  }
  private func clearActive() { lock.lock(); active = false; lock.unlock() }
}

/// A user-session signer application owns this listener and its approval UI.
/// Registering the launch agent is an explicit packaging/setup action, not a
/// side effect of a client opening the Wallet screen.
public final class SignerXPCServer: NSObject, NSXPCListenerDelegate {
  private let listener: NSXPCListener
  private let client: SignerCodeIdentity
  private let handler: @Sendable (Data) async throws -> Data
  public init(client: SignerCodeIdentity, handler: @escaping @Sendable (Data) async throws -> Data) {
    self.listener = NSXPCListener(machServiceName: SignerXPCClient.serviceName)
    self.client = client; self.handler = handler; super.init(); listener.delegate = self
  }
  public func activate() { listener.activate() }
  public func invalidate() { listener.invalidate() }
  public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
    guard connection.effectiveUserIdentifier == getuid() else { return false }
    connection.setCodeSigningRequirement(client.requirement)
    connection.exportedInterface = NSXPCInterface(with: CastaliaSignerXPC.self)
    connection.exportedObject = SignerXPCExport(handler: handler)
    connection.activate(); return true
  }
}
#endif
