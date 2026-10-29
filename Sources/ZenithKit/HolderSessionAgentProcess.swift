#if os(macOS)
import CryptoKit
import Darwin
import Foundation

/// Application-configured paths and hashes. These are never model arguments.
struct HolderSessionAgentLaunch: Sendable {
  let executable: URL, profileFile: URL
  let executableSHA256: String, profileSHA256: String
  func validate() throws -> HolderSessionAgentProfile {
    _ = try read(executable, digest: executableSHA256, privateFile: false, maximum: 64 * 1024 * 1024)
    return try .decode(read(profileFile, digest: profileSHA256, privateFile: true, maximum: 65536))
  }
  private func read(_ url: URL, digest: String, privateFile: Bool, maximum: Int) throws -> Data {
    _ = try HS.hex(digest, 64)
    guard url.isFileURL else { throw HolderSessionError.invalid }
    let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    guard fd >= 0 else { throw HolderSessionError.unsupported }
    let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
      info.st_size > 0, info.st_size <= maximum,
      info.st_uid == getuid() || (!privateFile && info.st_uid == 0),
      info.st_mode & (privateFile ? 0o077 : 0o022) == 0,
      !privateFile || info.st_nlink == 1,
      let data = try file.readToEnd(), data.count <= maximum,
      HS.digest(data) == digest else { throw HolderSessionError.changed }
    return data
  }
}

/// Temporary key custody only. EOF/process loss is terminal for this instance:
/// restarting never recreates a session identity under its original handle.
actor HolderSessionAgentProcess {
  private let launch: HolderSessionAgentLaunch
  private var process: Process?
  private var input: FileHandle?, output: FileHandle?
  private var errors: FileHandle?
  private var attempted = false, busy = false
  private var waiting = 0
  init(launch: HolderSessionAgentLaunch) { self.launch = launch }
  deinit {
    try? input?.close(); try? output?.close()
    if process?.isRunning == true { process?.terminate() }
  }
  func stop() {
    // An in-flight read owns its FileHandle until it returns. Do not close and
    // recycle that descriptor underneath the detached reader.
    try? input?.close(); input = nil; output = nil; errors = nil
    if process?.isRunning == true { process?.terminate() }
    process = nil; attempted = true
  }
  func create(expiresAt: UInt64, now: UInt64) async throws -> HolderSessionIdentity {
    let value = try await exchange(.create(expiresAt: expiresAt), now: now)
    return try .decode(value, service: launch.validate().provider.service, expiresAt: expiresAt)
  }
  func possession(_ challenge: HolderSessionChallenge, now: UInt64) async throws -> String {
    let value = try await exchange(.possession(session: challenge.intent.session.handle, challenge: challenge), now: now)
    return try HS.hex(HS.object(value)["session_signature"], 128)
  }
  func install(_ credential: HolderSessionCredential, now: UInt64) async throws {
    _ = try await exchange(.install(session: credential.challenge.intent.session.handle, credential: credential), now: now)
  }
  func present(_ credential: HolderSessionCredential, call: Data, now: UInt64) async throws -> Data {
    try await exchange(.present(session: credential.challenge.intent.session.handle, credential: credential, call: call), now: now)
  }
  func status(_ challenge: HolderSessionChallenge, now: UInt64) async throws -> Data {
    try await exchange(.status(session: challenge.intent.session.handle, challenge: challenge), now: now)
  }
  func close(_ identity: HolderSessionIdentity, now: UInt64) async throws {
    _ = try await exchange(.close(session: identity.handle), now: now)
  }
  private func exchange(_ command: HolderSessionAgentCommand, now: UInt64) async throws -> Data {
    guard waiting < 16 else { throw HolderSessionError.unsupported }
    waiting += 1; defer { waiting -= 1 }
    let queued = DispatchTime.now().uptimeNanoseconds
    while busy {
      try Task.checkCancellation()
      guard DispatchTime.now().uptimeNanoseconds - queued < 15_000_000_000 else { throw HolderSessionError.unsupported }
      try await Task.sleep(nanoseconds: 20_000_000)
    }
    try Task.checkCancellation()
    busy = true; defer { busy = false }
    let profile = try launch.validate()
    if process == nil {
      guard !attempted else { throw HolderSessionError.unsupported }
      attempted = true
      let child = Process(), stdin = Pipe(), stdout = Pipe(), stderr = Pipe()
      child.executableURL = launch.executable
      child.arguments = ["--profile-file", launch.profileFile.path]
      child.standardInput = stdin; child.standardOutput = stdout; child.standardError = stderr
      child.environment = ["PATH": "/usr/bin:/bin"]
      try child.run(); process = child
      input = stdin.fileHandleForWriting; output = stdout.fileHandleForReading; errors = stderr.fileHandleForReading
    }
    guard let child = process, child.isRunning, let input, let output, let errors else { stop(); throw HolderSessionError.custodyLost }
    let requestID = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    var frame = try HolderSessionAgentWire.request(command, requestID: requestID); frame.append(10)
    let request = frame
    do {
      let response = try await withTaskCancellationHandler(operation: {
        try await Task.detached { () throws -> Data in
          let timeout = DispatchWorkItem { if child.isRunning { child.terminate() } }
          DispatchQueue.global().asyncAfter(deadline: .now() + 15, execute: timeout)
          defer { timeout.cancel() }
          try input.write(contentsOf: request)
          var raw = Data(), buffer = [UInt8](repeating: 0, count: 4096)
          while raw.count < 131072 {
            let count = Darwin.read(output.fileDescriptor, &buffer, min(buffer.count, 131072 - raw.count))
            guard count > 0 else {
              // Decode only a fixed producer error; never echo child diagnostics
              // into an app/MCP result, journal or log.
              let diagnostic = try? errors.read(upToCount: 256)
              if diagnostic == Data("unsafe_profile\n".utf8) { throw HolderSessionError.unsafeHelperProfile }
              throw HolderSessionError.custodyLost
            }
            let bytes = Data(buffer.prefix(count))
            if let newline = bytes.firstIndex(of: 10) {
              guard newline == bytes.index(before: bytes.endIndex) else { throw HolderSessionError.invalid }
              raw.append(bytes[..<newline]); return raw
            }
            raw.append(bytes)
          }
          throw HolderSessionError.invalid
        }.value
      }, onCancel: { if child.isRunning { child.terminate() } })
      try Task.checkCancellation()
      return try HolderSessionAgentWire.response(response, requestID: requestID, command: command, profile: profile, now: UInt64(Date().timeIntervalSince1970))
    } catch {
      // Unknown/corrupt replies cannot be replayed on a fresh helper. Original
      // server outcomes remain recoverable only while their temporary key lives.
      stop(); throw error
    }
  }
}

extension HolderSessionAgentProcess: HolderSessionCustody {}
#endif
