import Foundation
import Combine

public enum PrivateNetworkPhase: Equatable, Sendable {
  case idle, connecting, signInRequired, awaitingApproval, connected, paused, failed
}
public enum PrivateNetworkError: Error, LocalizedError, Equatable {
  case disconnected, invalidStatus, interrupted, invalidAuthKey, enrollmentFailed
  public var errorDescription: String? {
    switch self {
    case .disconnected: return "Connect Tailscale in Connection before trying again."
    case .invalidAuthKey: return "Use a Tailscale auth key beginning with tskey-auth-."
    case .enrollmentFailed: return "Tailscale enrollment did not complete. Check that the auth key is valid, unexpired and unused, then try again. Your network may also require device approval."
    case .invalidStatus: return "The private connection could not be verified. Reconnect Tailscale to try again."
    case .interrupted: return "The private connection changed. Please try again."
    }
  }
}

/// Decode only the small subset needed by Zenith. Never retain peers, keys,
/// diagnostic messages, or a complete tailnet status document.
public struct PrivateNetworkStatus: Sendable {
  public let phase: PrivateNetworkPhase
  public let networkName: String?
  public let authURL: URL?
  public init(data: Data) throws {
    struct Status: Decodable {
      struct Tailnet: Decodable { let Name: String }
      let BackendState: String
      let AuthURL: String?
      let CurrentTailnet: Tailnet?
    }
    guard data.count <= 4_194_304 else { throw PrivateNetworkError.invalidStatus }
    let value = try JSONDecoder().decode(Status.self, from: data)
    switch value.BackendState {
    case "Running": phase = .connected
    case "NeedsLogin": phase = .signInRequired
    case "NeedsMachineAuth": phase = .awaitingApproval
    case "Starting", "NoState": phase = .connecting
    case "Stopped": phase = .paused
    default: throw PrivateNetworkError.invalidStatus
    }
    networkName = value.CurrentTailnet?.Name.count ?? 0 <= 256 ? value.CurrentTailnet?.Name : nil
    if phase == .signInRequired, let raw = value.AuthURL, !raw.isEmpty {
      // This release uses the official control plane only. A file cannot select
      // a control plane or redirect the sign-in UI to an arbitrary origin.
      guard raw.count <= 4096, let url = URL(string: raw), url.scheme == "https",
        url.host == "login.tailscale.com", url.port == nil || url.port == 443,
        url.user == nil, url.password == nil, url.fragment == nil
      else { throw PrivateNetworkError.invalidStatus }
      authURL = url
    } else { authURL = nil }
  }
}

public protocol PrivateNetworkDriver: Sendable {
  func start(interactive: Bool) async throws
  func enroll(authKey: String) async throws
  func status() async throws -> PrivateNetworkStatus
  func configuration() async throws -> URLSessionConfiguration
  func stop() async
}

/// Older drivers fail closed rather than silently starting browser sign-in.
public extension PrivateNetworkDriver {
  func enroll(authKey: String) async throws { throw PrivateNetworkError.enrollmentFailed }
}

/// Enrollment accepts an auth key, never an API token or an OAuth client secret.
/// This is transient input, independent of Wallet and gateway connection files.
public enum TailscaleEnrollment {
  public static func validatedKey(_ raw: String) throws -> String {
    let key = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    guard (32...512).contains(key.utf8.count), key.hasPrefix("tskey-auth-"),
      key.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0)
        || (48...57).contains($0) || $0 == 45 })
    else { throw PrivateNetworkError.invalidAuthKey }
    return key
  }
  public static func importKey(_ data: Data) throws -> String {
    guard data.count <= 1024, let text = String(data: data, encoding: .utf8) else {
      throw PrivateNetworkError.invalidAuthKey
    }
    return try validatedKey(text)
  }
}

/// A task may poll for minutes; don't retain its submitted key in that closure.
@MainActor
private final class PendingEnrollment {
  private var value: String?
  init(_ value: String) { self.value = value }
  func take() -> String? { defer { value = nil }; return value }
}

/// App-scoped network lifecycle, independent of custody and read authority.
/// Every generation invalidates its HTTP sessions; cancellation never enables
/// a direct-network fallback. Driver calls are serialized across stop/restart.
@MainActor
public final class PrivateNetworkSession: ObservableObject {
  @Published public private(set) var phase: PrivateNetworkPhase = .idle
  @Published public private(set) var networkName: String?
  @Published public private(set) var authURL: URL?
  @Published public private(set) var message: String?
  @Published public private(set) var generation = 0
  private let driver: any PrivateNetworkDriver
  private var operation: Task<Void, Never>?
  private var resumeRequested = false
  private var enrollmentInput: PendingEnrollment?
  private struct WeakTransport { weak var value: PrivateTransport? }
  private var transports: [WeakTransport] = []
  public init(driver: any PrivateNetworkDriver) { self.driver = driver }

  public func connect() { begin(interactive: true) }
  public func enroll(authKey: String) throws {
    let pending = PendingEnrollment(try TailscaleEnrollment.validatedKey(authKey))
    begin(interactive: false, enrollment: pending)
  }
  public func disconnect() { stop(phase: .idle, resume: false) }
  public func cancelSignIn() { disconnect() }
  public func suspend() {
    let wanted = phase != .idle && phase != .failed
    stop(phase: wanted ? .paused : .idle, resume: wanted)
  }
  public func resume() {
    guard resumeRequested else { return }
    resumeRequested = false
    begin(interactive: false)
  }
  public func transport(requestTimeout: TimeInterval = 20, resourceTimeout: TimeInterval = 30) -> PrivateTransport {
    let transport = PrivateTransport(configurationProvider: { [weak self] in
      guard let self else { throw PrivateNetworkError.disconnected }
      return try await self.configuration()
    }, requestTimeout: requestTimeout, resourceTimeout: resourceTimeout)
    transports.removeAll { $0.value == nil }
    transports.append(WeakTransport(value: transport))
    return transport
  }
  private func invalidate() {
    _ = enrollmentInput?.take()
    enrollmentInput = nil
    generation += 1
    authURL = nil
    networkName = nil
    transports.forEach { $0.value?.cancel() }
    transports.removeAll { $0.value == nil }
  }
  private func stop(phase next: PrivateNetworkPhase, resume: Bool) {
    resumeRequested = resume
    let previous = operation
    previous?.cancel()
    invalidate()
    phase = next
    message = nil
    operation = Task { [driver] in
      await previous?.value
      await driver.stop()
    }
  }
  private func startDriver(interactive: Bool, enrollment: PendingEnrollment?) async throws {
    if let key = enrollment?.take() { try await driver.enroll(authKey: key) }
    else { try await driver.start(interactive: interactive) }
  }
  private func begin(interactive: Bool, enrollment: PendingEnrollment? = nil) {
    let previous = operation
    previous?.cancel()
    invalidate()
    enrollmentInput = enrollment
    let ticket = generation
    phase = .connecting
    message = nil
    resumeRequested = false
    operation = Task { [weak self, driver] in
      await previous?.value
      await driver.stop()
      do {
        try Task.checkCancellation()
        try await self?.startDriver(interactive: interactive, enrollment: enrollment)
        let started = Date()
        while !Task.isCancelled {
          let status = try await driver.status()
          guard let self, ticket == self.generation, !Task.isCancelled else { break }
          if self.phase == .connected && status.phase != .connected {
            self.transports.forEach { $0.value?.cancel() }
            self.generation += 1
            self.phase = status.phase
            self.authURL = nil
            self.message = "Tailscale disconnected. Reconnect to continue."
            break
          }
          // Key enrollment never presents browser authentication, including
          // when an invalid key makes the control plane return NeedsLogin.
          self.phase = enrollment != nil && status.phase == .signInRequired ? .connecting : status.phase
          self.networkName = status.networkName
          self.authURL = enrollment == nil ? status.authURL : nil
          let timeout: TimeInterval = enrollment == nil || status.phase == .awaitingApproval ? 300 : 45
          if status.phase != .connected && Date().timeIntervalSince(started) > timeout {
            throw PrivateNetworkError.disconnected
          }
          try await Task.sleep(nanoseconds: status.phase == .connected ? 5_000_000_000 : 1_000_000_000)
        }
      } catch {
        if let self, ticket == self.generation, !Task.isCancelled {
          self.invalidate()
          self.phase = .failed
          self.message = enrollment == nil
            ? "Couldn’t connect Tailscale. Check your internet connection and try again."
            : PrivateNetworkError.enrollmentFailed.localizedDescription
        }
      }
      await driver.stop()
    }
  }
  private func configuration() async throws -> URLSessionConfiguration {
    guard phase == .connected else { throw PrivateNetworkError.disconnected }
    let ticket = generation
    let status = try await driver.status()
    guard status.phase == .connected else { throw PrivateNetworkError.disconnected }
    let config = try await driver.configuration()
    guard ticket == generation, phase == .connected else { throw PrivateNetworkError.interrupted }
    return config
  }
}
