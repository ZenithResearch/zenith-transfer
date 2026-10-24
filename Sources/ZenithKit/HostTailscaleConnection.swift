#if os(macOS)
import Darwin
import Foundation

public enum HostTailscaleFailure: Error, LocalizedError {
  case unavailable, alreadyConnected, failed
  public var errorDescription: String? {
    switch self {
    case .unavailable: return "Install or open the official Tailscale app on this Mac, then refresh."
    case .alreadyConnected: return "This Mac is already connected. Use its current connection, or change networks in Tailscale before using an enrollment file."
    case .failed: return "Tailscale could not finish enrollment. Check that the key is unused and unexpired, and ask your administrator whether this device needs approval."
    }
  }
}

/// Uses the existing host node. Only an explicit Connect action invokes `up`.
/// A file cannot choose an executable, control server, routes, tags or exit node.
public struct HostTailscaleConnection: Sendable {
  public typealias Command = @Sendable ([String]) async throws -> Data
  private let command: Command
  public init(command: @escaping Command = { try await HostTailscaleConnection.run($0) }) { self.command = command }
  public func status() async throws -> PrivateNetworkStatus {
    try PrivateNetworkStatus(data: await command(["status", "--json"]))
  }
  /// macOS uses the installed Tailscale node and OS routing. Verify the host
  /// connection before each request; never select the iOS direct-route fallback.
  public func configuration() async throws -> URLSessionConfiguration {
    guard try await status().phase == .connected else { throw PrivateNetworkError.disconnected }
    let config = URLSessionConfiguration.ephemeral
    config.connectionProxyDictionary = [:]; config.httpShouldSetCookies = false
    config.httpCookieStorage = nil; config.urlCredentialStorage = nil; config.urlCache = nil
    return config
  }
  public func transport() -> PrivateTransport {
    PrivateTransport(configurationProvider: { try await self.configuration() })
  }
  public func connect(using review: ConnectionFileReview) async throws -> PrivateNetworkStatus {
    let before = try await status()
    guard before.phase != .connected, before.networkName == nil else { throw HostTailscaleFailure.alreadyConnected }
    guard before.phase == .signInRequired || before.phase == .idle || before.phase == .paused else { throw HostTailscaleFailure.failed }
    try Task.checkCancellation()
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: directory) }
    let input = directory.appendingPathComponent("enrollment.key")
    try NetworkConnectionFiles.saveEnrollmentKey(review.selectedEnrollmentKey(), to: input)
    // Never put the key in argv/environment/logs. The official CLI reads this
    // private, exact reviewed snapshot, which is removed when this call ends.
    do { _ = try await command(["up", "--auth-key=file:" + input.path, "--timeout=30s"]) }
    catch is CancellationError { throw CancellationError() }
    catch { /* A device awaiting approval may make `up` time out. Read status. */ }
    try Task.checkCancellation()
    let after = try await status()
    guard after.phase == .connected || after.phase == .awaitingApproval else { throw HostTailscaleFailure.failed }
    return after
  }
  public static func run(_ arguments: [String]) async throws -> Data {
    let worker = Task.detached(priority: .userInitiated) { () async throws -> Data in
      let executable = URL(fileURLWithPath: "/Applications/Tailscale.app/Contents/MacOS/Tailscale")
      guard FileManager.default.isExecutableFile(atPath: executable.path) else { throw HostTailscaleFailure.unavailable }
      let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
      try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
      defer { try? FileManager.default.removeItem(at: folder) }
      let output = folder.appendingPathComponent("response")
      guard FileManager.default.createFile(atPath: output.path, contents: nil, attributes: [.posixPermissions: 0o600]) else { throw HostTailscaleFailure.failed }
      let handle = try FileHandle(forWritingTo: output); defer { try? handle.close() }
      let process = Process(); process.executableURL = executable; process.arguments = arguments
      process.standardInput = FileHandle.nullDevice; process.standardOutput = handle; process.standardError = FileHandle.nullDevice
      defer {
        if process.isRunning { process.terminate(); if process.isRunning { Darwin.kill(process.processIdentifier, SIGKILL) }; process.waitUntilExit() }
      }
      try Task.checkCancellation(); try process.run()
      let deadline = ProcessInfo.processInfo.systemUptime + (arguments.first == "up" ? 35 : 10)
      while process.isRunning {
        try Task.checkCancellation()
        let size = (try? FileManager.default.attributesOfItem(atPath: output.path)[.size] as? NSNumber)?.intValue ?? 1_048_577
        guard size <= 1_048_576, ProcessInfo.processInfo.systemUptime < deadline else { throw HostTailscaleFailure.failed }
        try await Task.sleep(nanoseconds: 20_000_000)
      }
      guard process.terminationStatus == 0 else { throw HostTailscaleFailure.failed }
      if arguments.first == "up" { return Data() }
      return try NetworkConnectionFiles.read(output, maximum: 1_048_576)
    }
    return try await withTaskCancellationHandler(operation: { try await worker.value }, onCancel: { worker.cancel() })
  }
}
#endif
