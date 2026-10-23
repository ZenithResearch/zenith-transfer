#if os(macOS)
import CryptoKit
import Darwin
import Foundation

public enum LocalAdminRPCError: LocalizedError {
  case unavailable, changed, resultUnknown
  public var errorDescription: String? {
    switch self {
    case .unavailable: return "Local secS administration is not installed for this service. Its HTTPS connection and saved actions are preserved."
    case .changed: return "The local service or verification settings changed. Refresh and select the service again."
    case .resultUnknown: return "The local command’s result is not confirmed. Keep the original action and check its status before submitting another decision."
    }
  }
}

/// An additive local service binding, separate from portable HTTPS profiles.
/// The registry selects the receiver; Wallet signatures authorize every action.
public struct LocalAdminRPC: Sendable {
  public let resourceID: String
  public let instanceID: String
  public let receiver: String
  public let issuer: String
  public let profileSHA256: String
  public let executableSHA256: String
  private let home: URL
  public static func profileDigest(_ configuration: WorkAccessConfiguration) throws -> String {
    let raw = try JSONSerialization.jsonObject(with: JSONEncoder().encode(configuration))
    return OwnerSetupPlan.sha256(try OwnerReviewCanonicalJSON.encode(raw))
  }
  static func decode(_ data: Data, service: LocalService, home: URL) throws -> Self {
    var strict = OwnerPlanJSON(data, maximumBytes: 65536, maximumKeys: 2000)
    try strict.validate()
    guard let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(raw.keys) == ["schema","resource_id","instance_id","receiver","issuer","profile_sha256","rpc_binary_sha256","python","python_sha256","source","runtime","data_root","name","source_files"],
      let schema = raw["schema"] as? String,
      schema == "secs.local-admin-config.v1",
      service.interface == .walletAPI, let configuration = service.connection,
      configuration.network == .local,
      raw["resource_id"] as? String == service.resource_id,
      raw["instance_id"] as? String == service.id, raw["receiver"] as? String == service.endpoint,
      raw["issuer"] as? String == configuration.issuer,
      raw["profile_sha256"] as? String == (try profileDigest(configuration)),
      let executable = raw["rpc_binary_sha256"] as? String,
      executable.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil
    else { throw LocalAdminRPCError.changed }
    return Self(resourceID: service.resource_id, instanceID: service.id, receiver: service.endpoint,
      issuer: configuration.issuer, profileSHA256: try profileDigest(configuration), executableSHA256: executable,
      home: home)
  }
  public static func discover(configuration: WorkAccessConfiguration, home: URL = FileManager.default.homeDirectoryForCurrentUser) throws -> Self {
    guard configuration.network == .local else { throw LocalAdminRPCError.unavailable }
    let matches = LocalServiceDiscovery.scan(home: home).services.filter { $0.interface == .walletAPI && $0.connection == configuration }
    guard matches.count == 1, let service = matches.first else { throw LocalAdminRPCError.changed }
    let file = home.appendingPathComponent(".zenith/rpc/v1/\(service.id).json")
    try safeParents(file, home: home)
    return try decode(OwnerSetupInspector.privateData(file, maximum: 65536), service: service, home: home)
  }
  private static func safeParents(_ url: URL, home: URL) throws {
    guard url.path.hasPrefix(home.path + "/"), url.standardizedFileURL.path == url.path else { throw LocalAdminRPCError.changed }
    var parent = url.deletingLastPathComponent()
    while parent.path != home.path {
      var info = stat()
      guard lstat(parent.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
        [getuid(), 0].contains(info.st_uid), info.st_mode & 0o022 == 0 else { throw LocalAdminRPCError.unavailable }
      parent.deleteLastPathComponent()
    }
  }
  func envelope(operation: String, body: Data, requestID: String) throws -> Data {
    guard ["inspect","challenge","execute"].contains(operation), body.count <= 65536 else { throw LocalAdminRPCError.changed }
    var strict = OwnerPlanJSON(body, maximumBytes: 65536); try strict.validate()
    let value = try JSONSerialization.jsonObject(with: body)
    let raw: [String: Any] = ["schema":"secs.local-admin-request.v1", "request_id":requestID,
      "resource_id":resourceID,"instance_id":instanceID,"receiver":receiver,"issuer":issuer,
      "profile_sha256":profileSHA256,"operation":operation,"body":value]
    let encoded = try OwnerReviewCanonicalJSON.encode(raw)
    guard encoded.count <= 65536 else { throw LocalAdminRPCError.changed }; return encoded
  }
  func response(_ data: Data, requestID: String) throws -> PrivateHTTPResponse {
    var strict = OwnerPlanJSON(data, maximumBytes: 1_048_576, maximumKeys: 6000, maximumArray: 6000, maximumDepth: 24)
    try strict.validate()
    guard let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      Set(raw.keys) == ["schema","request_id","resource_id","instance_id","receiver","status","body"],
      raw["schema"] as? String == "secs.local-admin-response.v1",
      raw["request_id"] as? String == requestID, raw["resource_id"] as? String == resourceID,
      raw["instance_id"] as? String == instanceID, raw["receiver"] as? String == receiver,
      let status = raw["status"] as? Int, [200,400,401,403,409,503].contains(status),
      let body = raw["body"] as? [String: Any] else { throw LocalAdminRPCError.resultUnknown }
    return PrivateHTTPResponse(status: status, data: try OwnerReviewCanonicalJSON.encode(body))
  }
  public func call(operation: String, body: Data) async throws -> PrivateHTTPResponse {
    let requestID = UUID().uuidString.lowercased()
    let input = try envelope(operation: operation, body: body, requestID: requestID)
    return try await Task.detached {
      let executable = home.appendingPathComponent("Library/Application Support/Zenith/secS/bin/secs-local-admin-rpc-v1")
      try Self.safeParents(executable, home: home)
      let binary = try OwnerSetupInspector.privateData(executable, maximum: 20_000_000)
      guard OwnerSetupPlan.sha256(binary) == executableSHA256 else { throw LocalAdminRPCError.changed }
      var info = stat()
      guard lstat(executable.path, &info) == 0, info.st_mode & 0o100 != 0 else { throw LocalAdminRPCError.unavailable }
      let process = Process(), output = Pipe(), stdin = Pipe()
      process.executableURL = executable; process.arguments = ["--instance-id",instanceID]
      process.environment = ["PATH":"/usr/bin:/bin:/usr/sbin:/sbin","LANG":"en_US.UTF-8"]
      process.standardInput = stdin; process.standardOutput = output; process.standardError = FileHandle.nullDevice
      try process.run()
      let timeout = DispatchWorkItem { if process.isRunning { process.terminate() } }
      DispatchQueue.global().asyncAfter(deadline: .now() + 40, execute: timeout)
      defer { timeout.cancel() }
      do { try stdin.fileHandleForWriting.write(contentsOf: input); try stdin.fileHandleForWriting.close() }
      catch { if process.isRunning { process.terminate() }; throw LocalAdminRPCError.resultUnknown }
      var raw = Data()
      while let bytes = try output.fileHandleForReading.read(upToCount: 65536), !bytes.isEmpty {
        raw.append(bytes)
        guard raw.count <= 1_048_576 else { if process.isRunning { process.terminate() }; throw LocalAdminRPCError.resultUnknown }
      }
      process.waitUntilExit()
      guard process.terminationStatus == 0 else { throw LocalAdminRPCError.resultUnknown }
      return try response(raw, requestID: requestID)
    }.value
  }
}
#endif
