#if os(macOS)
import CryptoKit
import Darwin
import Foundation

public enum SessionReviewBridgeError: Error { case unavailable, invalid, unauthorized }

/// Local request/scoped-call channel, not the isolated signer XPC transport.
/// Same-UID peers with the private pairing token cannot approve or sign.
/// This is not a security boundary against a compromised process of that user.
public final class SessionReviewSocket: @unchecked Sendable {
  public static var defaultDirectory: URL { URL(fileURLWithPath: "/tmp/zenith-transfer-\(getuid())", isDirectory: true) }
  private let directory: URL
  private let handler: @Sendable (String, String, Data) async throws -> Data
  private let mutex = NSLock()
  private var listener: Int32 = -1
  private var lease: Int32 = -1
  private var token = ""
  private var generation: UInt64 = 0
  private let queue = DispatchQueue(label: "ca.zenith.transfer.review-socket")
  public init(directory: URL = SessionReviewSocket.defaultDirectory,
    handler: @escaping @Sendable (String, String, Data) async throws -> Data) {
    self.directory = directory; self.handler = handler
  }
  deinit { stop() }
  public func start() throws {
    mutex.lock(); defer { mutex.unlock() }
    guard listener == -1 else { return }
    let fm = FileManager.default
    if !fm.fileExists(atPath: directory.path) {
      try fm.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }
    var info = stat()
    guard lstat(directory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
      info.st_uid == getuid(), info.st_mode & 0o077 == 0 else { throw SessionReviewBridgeError.unauthorized }
    let lock = open(directory.appendingPathComponent("broker.lock").path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard lock >= 0 else { throw SessionReviewBridgeError.unavailable }
    guard fstat(lock, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
      info.st_mode & 0o077 == 0, flock(lock, LOCK_EX | LOCK_NB) == 0 else {
      close(lock); throw SessionReviewBridgeError.unavailable
    }
    let path = directory.appendingPathComponent("review.sock").path
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { close(lock); throw SessionReviewBridgeError.unavailable }
    _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
    do {
      var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
      let name = Array(path.utf8) + [0]
      guard name.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw SessionReviewBridgeError.invalid }
      withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: name) }
      address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
      if lstat(path, &info) == 0 {
        guard info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFSOCK else { throw SessionReviewBridgeError.unauthorized }
        guard unlink(path) == 0 else { throw SessionReviewBridgeError.unavailable }
      }
      let bound = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
      }
      guard bound == 0, chmod(path, 0o600) == 0, Darwin.listen(fd, 8) == 0 else { throw SessionReviewBridgeError.unavailable }
      let tokenURL = directory.appendingPathComponent("pairing-token")
      let secret = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0).map { String(format: "%02x", $0) }.joined() }
      let keyFile = open(tokenURL.path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
      guard keyFile >= 0 else { throw SessionReviewBridgeError.unavailable }
      defer { close(keyFile) }
      guard fstat(keyFile, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
        info.st_mode & 0o077 == 0, info.st_nlink == 1, ftruncate(keyFile, 0) == 0 else { throw SessionReviewBridgeError.unauthorized }
      let bytes = Array(secret.utf8)
      guard bytes.withUnsafeBytes({ Darwin.write(keyFile, $0.baseAddress, $0.count) }) == bytes.count else { throw SessionReviewBridgeError.unavailable }
      token = secret; lease = lock; listener = fd; generation &+= 1
      let epoch = generation
      queue.async { [weak self] in self?.serve(fd, epoch: epoch) }
    } catch { close(fd); close(lock); throw error }
  }
  public func stop() {
    mutex.lock(); let fd = listener, lock = lease; listener = -1; lease = -1; token = ""; generation &+= 1; mutex.unlock()
    guard fd >= 0 else { return }
    shutdown(fd, SHUT_RDWR); close(fd)
    _ = unlink(directory.appendingPathComponent("review.sock").path)
    _ = unlink(directory.appendingPathComponent("pairing-token").path)
    if lock >= 0 { _ = flock(lock, LOCK_UN); close(lock) }
  }
  private func serve(_ fd: Int32, epoch: UInt64) {
    while true {
      mutex.lock(); let current = listener == fd && generation == epoch; mutex.unlock()
      guard current else { return }
      let peer = accept(fd, nil, nil)
      guard peer >= 0 else { return }
      _ = fcntl(peer, F_SETFD, FD_CLOEXEC)
      handle(peer); close(peer)
    }
  }
  private func handle(_ fd: Int32) {
    var uid: uid_t = 0, gid: gid_t = 0
    guard getpeereid(fd, &uid, &gid) == 0, uid == getuid() else { return }
    var timeout = timeval(tv_sec: 5, tv_usec: 0)
    _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    var noSignal: Int32 = 1
    _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
    var callID = ""
    do {
      let prefix = try read(fd, count: 4)
      let length = prefix.reduce(0) { ($0 << 8) | Int($1) }
      guard (1...65536).contains(length) else { throw SessionReviewBridgeError.invalid }
      let raw = try read(fd, count: length)
      var strict = OwnerPlanJSON(raw, maximumBytes: 65536, maximumKeys: 256, maximumArray: 256, maximumDepth: 24, allowNegativeIntegers: true)
      try strict.validate()
      guard let value = try JSONSerialization.jsonObject(with: raw) as? [String: Any],
        Set(value.keys) == ["schema", "call_id", "client_id", "token", "method", "params"],
        value["schema"] as? String == "zenith.session-review-ipc.v1",
        let call = value["call_id"] as? String, validID(call), let client = value["client_id"] as? String, validID(client),
        let supplied = value["token"] as? String,
        let method = value["method"] as? String, ["list_services", "request_review", "get_result", "execute", "close_client"].contains(method),
        let params = value["params"] as? [String: Any] else { throw SessionReviewBridgeError.invalid }
      callID = call
      mutex.lock(); let expected = token; mutex.unlock()
      guard !expected.isEmpty, supplied.utf8.count == 64,
        SHA256.hash(data: Data(supplied.utf8)) == SHA256.hash(data: Data(expected.utf8)) else { throw SessionReviewBridgeError.unauthorized }
      let input = try OwnerReviewCanonicalJSON.encode(params), completion = SocketCompletion()
      Task {
        do { completion.finish(.success(try await handler(client, method, input))) }
        catch { completion.finish(.failure(SessionReviewBridgeError.unavailable)) }
      }
      guard completion.signal.wait(timeout: .now() + 10) == .success else { throw SessionReviewBridgeError.unavailable }
      let result = try completion.value().get()
      guard result.count <= 60000, let object = try JSONSerialization.jsonObject(with: result) as? [String: Any] else { throw SessionReviewBridgeError.invalid }
      try send(fd, object: ["schema": "zenith.session-review-ipc-result.v1", "call_id": callID, "result": object])
    } catch {
      try? send(fd, object: ["schema": "zenith.session-review-ipc-result.v1", "call_id": callID, "error": "wallet_review_unavailable"])
    }
  }
  private func validID(_ text: String) -> Bool { text.utf8.count == 32 && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
  private func read(_ fd: Int32, count: Int) throws -> Data {
    var data = Data(count: count), cursor = 0
    try data.withUnsafeMutableBytes { bytes in
      while cursor < count {
        let n = Darwin.read(fd, bytes.baseAddress!.advanced(by: cursor), count - cursor)
        guard n > 0 else { throw SessionReviewBridgeError.unavailable }; cursor += n
      }
    }
    return data
  }
  private func send(_ fd: Int32, object: [String: Any]) throws {
    let payload = try OwnerReviewCanonicalJSON.encode(object)
    var size = UInt32(payload.count).bigEndian
    var data = withUnsafeBytes(of: &size) { Data($0) }; data.append(payload)
    try data.withUnsafeBytes { bytes in
      var cursor = 0
      while cursor < data.count {
        let n = Darwin.write(fd, bytes.baseAddress!.advanced(by: cursor), data.count - cursor)
        guard n > 0 else { throw SessionReviewBridgeError.unavailable }; cursor += n
      }
    }
  }
}
private final class SocketCompletion: @unchecked Sendable {
  let signal = DispatchSemaphore(value: 0)
  private let lock = NSLock()
  private var result: Result<Data, Error> = .failure(SessionReviewBridgeError.unavailable)
  func finish(_ value: Result<Data, Error>) { lock.lock(); result = value; lock.unlock(); signal.signal() }
  func value() -> Result<Data, Error> { lock.lock(); defer { lock.unlock() }; return result }
}
#endif
