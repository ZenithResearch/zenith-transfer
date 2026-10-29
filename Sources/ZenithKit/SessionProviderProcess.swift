#if os(macOS)
import CryptoKit
import Darwin
import Foundation

/// Explicit private launch binding. No field is accepted from MCP tool input.
/// Production registration must supply a reviewed source dependency inventory.
public struct SessionProviderLaunch: Sendable {
  public let interpreter: URL, script: URL, profile: URL
  public let interpreterSHA256: String, scriptSHA256: String, profileSHA256: String
  public let sources: [URL: String]
  public init(interpreter: URL, script: URL, profile: URL, interpreterSHA256: String,
    scriptSHA256: String, profileSHA256: String, sources: [URL: String]) {
    self.interpreter = interpreter.standardizedFileURL; self.script = script; self.profile = profile
    self.interpreterSHA256 = interpreterSHA256; self.scriptSHA256 = scriptSHA256; self.profileSHA256 = profileSHA256; self.sources = sources
  }
  public func validate() throws {
    guard !sources.isEmpty, sources.count <= 1024 else { throw SessionReviewBridgeError.invalid }
    // Preserve the explicit venv invocation path; resolving it for execution
    // would lose pyvenv.cfg and load a different Python dependency environment.
    try verify(interpreter.resolvingSymlinksInPath(), digest: interpreterSHA256, privateFile: false, maximum: 64 * 1024 * 1024)
    try verify(script, digest: scriptSHA256, privateFile: false, maximum: 1048576)
    try verify(profile, digest: profileSHA256, privateFile: true, maximum: 65536)
    // The reviewed inventory also contains native custody binaries, not only
    // Python text. Bound both individual files and the entire inventory.
    var sourceBytes = 0
    for (url, digest) in sources {
      sourceBytes += try verify(url, digest: digest, privateFile: false, maximum: 64 * 1024 * 1024)
      guard sourceBytes <= 256 * 1024 * 1024 else { throw SessionReviewBridgeError.invalid }
    }
  }
  @discardableResult private func verify(_ url: URL, digest: String, privateFile: Bool, maximum: Int) throws -> Int {
    guard url.isFileURL, digest.range(of: "\\A[0-9a-f]{64}\\z", options: .regularExpression) != nil else { throw SessionReviewBridgeError.invalid }
    let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    guard fd >= 0 else { throw SessionReviewBridgeError.unavailable }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_size > 0, info.st_size <= maximum,
      (info.st_uid == getuid() || (!privateFile && info.st_uid == 0)), info.st_mode & (privateFile ? 0o077 : 0o022) == 0,
      !privateFile || info.st_nlink == 1,
      let data = try handle.readToEnd(), data.count <= maximum,
      OwnerSetupPlan.sha256(data) == digest else { throw SessionReviewBridgeError.unauthorized }
    return data.count
  }
}

/// One long-lived private provider process. A failed process is never replaced
/// inside this instance: its session keys may be gone and cannot be recreated
/// under an old request/credential handle. No key material is returned to MCP.
public actor SessionProviderProcess {
  private let launch: SessionProviderLaunch
  private var process: Process?
  private var input: FileHandle?, output: FileHandle?
  private var attemptedStart = false
  private var busy = false
  private var waiting = 0
  public init(launch: SessionProviderLaunch) { self.launch = launch }
  public func stop() {
    try? input?.close(); input = nil; output = nil
    if process?.isRunning == true { process?.terminate() }
    process = nil; attemptedStart = true
  }
  public func exchange(clientID: String, operation: String, arguments: Data) async throws -> Data {
    guard ["services", "prepare", "update_expiry", "owner_challenge", "submit", "reconcile", "execute", "close_client"].contains(operation)
    else { throw SessionReviewBridgeError.unavailable }
    return try await exchangeEnvelope(clientID: clientID, operation: operation, arguments: arguments,
      commandSchema: "devgraph.session-provider-command.v1", resultSchema: "devgraph.session-provider-result.v1")
  }
  // Separate typed entry point; callers cannot choose a protocol/schema or pass
  // an arbitrary operation through the new holder-session channel.
  func exchangeHolder(clientID: String, command: HolderSessionBrokerCommand) async throws -> Data {
    try await exchangeEnvelope(clientID: clientID, operation: command.operation, arguments: command.arguments(),
      commandSchema: "devgraph.holder-session-provider-command.v1", resultSchema: "devgraph.holder-session-provider-result.v1")
  }
  private func exchangeEnvelope(clientID: String, operation: String, arguments: Data,
    commandSchema: String, resultSchema: String) async throws -> Data {
    guard clientID.range(of: "\\A[0-9a-f]{32}\\z", options: .regularExpression) != nil else { throw SessionReviewBridgeError.unavailable }
    // UI approval and another adapter's status check may arrive together. Keep
    // one NDJSON exchange in flight instead of failing a signed dispatch merely
    // because a harmless read currently owns the pipe. The queue is bounded.
    guard waiting < 16 else { throw SessionReviewBridgeError.unavailable }
    waiting += 1; defer { waiting -= 1 }
    let queuedAt = DispatchTime.now().uptimeNanoseconds
    while busy {
      try Task.checkCancellation()
      guard DispatchTime.now().uptimeNanoseconds - queuedAt < 15_000_000_000 else { throw SessionReviewBridgeError.unavailable }
      try await Task.sleep(nanoseconds: 20_000_000)
    }
    try Task.checkCancellation()
    busy = true; defer { busy = false }
    try launch.validate()
    var argumentReader = OwnerPlanJSON(arguments, maximumBytes: 262144, maximumKeys: 256, maximumArray: 256, maximumDepth: 24, allowNegativeIntegers: true)
    try argumentReader.validate()
    guard let args = try JSONSerialization.jsonObject(with: arguments) as? [String: Any] else { throw SessionReviewBridgeError.invalid }
    if process == nil {
      guard !attemptedStart else { throw SessionReviewBridgeError.unavailable }
      attemptedStart = true
      let child = Process(), stdin = Pipe(), stdout = Pipe()
      child.executableURL = launch.interpreter
      child.arguments = ["-I", launch.script.path, "--profile-file", launch.profile.path]
      child.standardInput = stdin; child.standardOutput = stdout; child.standardError = FileHandle.nullDevice
      var env = ["PATH": "/usr/bin:/bin"]
      for key in ["LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TZ"] {
        if let value = ProcessInfo.processInfo.environment[key] { env[key] = value }
      }
      child.environment = env
      try child.run(); process = child; input = stdin.fileHandleForWriting; output = stdout.fileHandleForReading
    }
    guard let child = process, child.isRunning, let input, let output else { throw SessionReviewBridgeError.unavailable }
    let requestID = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    var wire = try SessionReviewWire.encode(["schema": commandSchema, "request_id": requestID,
      "client_id": clientID, "operation": operation, "arguments": args])
    guard wire.count < 262144 else { throw SessionReviewBridgeError.invalid }; wire.append(10)
    let request = wire
    do {
      let response = try await Task.detached { () throws -> Data in
        let timeout = DispatchWorkItem { if child.isRunning { child.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 15, execute: timeout)
        defer { timeout.cancel() }
        try input.write(contentsOf: request)
        var raw = Data(), buffer = [UInt8](repeating: 0, count: 4096)
        while raw.count < 262144 {
          let count = Darwin.read(output.fileDescriptor, &buffer, buffer.count)
          guard count > 0 else { throw SessionReviewBridgeError.unavailable }
          let bytes = Data(buffer.prefix(count))
          if let newline = bytes.firstIndex(of: 10) {
            guard newline == bytes.index(before: bytes.endIndex) else { throw SessionReviewBridgeError.invalid }
            raw.append(bytes[..<newline]); return raw
          }
          raw.append(bytes)
        }
        throw SessionReviewBridgeError.invalid
      }.value
      // Only the private provider channel may carry crypto envelopes. Its parser
      // has the larger frame budget; model-facing responses stay below64KiB.
      var strict = OwnerPlanJSON(response, maximumBytes: 262144, maximumKeys: 256, maximumArray: 256, maximumDepth: 24, allowNegativeIntegers: true)
      try strict.validate()
      guard let value = try JSONSerialization.jsonObject(with: response) as? [String: Any],
        value["schema"] as? String == resultSchema, value["request_id"] as? String == requestID,
        let ok = value["ok"] as? NSNumber, CFGetTypeID(ok) == CFBooleanGetTypeID(),
        Set(value.keys) == (ok.boolValue ? ["schema", "request_id", "ok", "value"] : ["schema", "request_id", "ok", "error"])
      else { throw SessionReviewBridgeError.invalid }
      guard ok.boolValue, let body = value["value"] else { throw SessionReviewBridgeError.unavailable }
      return try SessionReviewWire.encode(body)
    } catch {
      // Even a lost reply can follow a completed issuer action. Keep this process
      // reference and let the original request reconcile if it is still alive.
      if case SessionReviewBridgeError.invalid = error { stop() }
      else if !child.isRunning { stop() }
      throw error
    }
  }
}
#endif
