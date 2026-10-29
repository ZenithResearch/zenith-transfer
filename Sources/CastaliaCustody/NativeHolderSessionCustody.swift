import CastaliaWallet
import Foundation
import ZenithKit

/// In-process temporary custody for platforms without child processes. It has a
/// separate opaque Core handle; closing or locking the root Wallet cannot sign
/// session calls and cannot recreate this session key. No key bytes cross ABI.
public actor NativeHolderSessionCustody: HolderSessionCustody {
  private var handle: UInt64
  private let profile: HolderSessionAgentProfile
  public init(profileData: Data) throws {
    profile = try .decode(profileData)
    guard castalia_holder_session_abi_version() == 1 else { throw HolderSessionError.unsupported }
    handle = profileData.withUnsafeBytes { castalia_holder_session_new($0.bindMemory(to: UInt8.self).baseAddress, profileData.count) }
    guard handle != 0 else { throw HolderSessionError.invalid }
  }
  deinit { if handle != 0 { castalia_holder_session_free(handle) } }
  public func stop() { if handle != 0 { castalia_holder_session_free(handle); handle = 0 } }
  public func create(expiresAt: UInt64, now: UInt64) throws -> HolderSessionIdentity {
    try .decode(invoke(.create(expiresAt: expiresAt), now: now), service: profile.provider.service, expiresAt: expiresAt)
  }
  public func possession(_ challenge: HolderSessionChallenge, now: UInt64) throws -> String {
    let data = try invoke(.possession(session: challenge.intent.session.handle, challenge: challenge), now: now)
    struct Signature: Decodable { let session_signature: String }
    return try JSONDecoder().decode(Signature.self, from: data).session_signature
  }
  public func install(_ credential: HolderSessionCredential, now: UInt64) throws {
    _ = try invoke(.install(session: credential.challenge.intent.session.handle, credential: credential), now: now)
  }
  public func present(_ credential: HolderSessionCredential, call: Data, now: UInt64) throws -> Data {
    try invoke(.present(session: credential.challenge.intent.session.handle, credential: credential, call: call), now: now)
  }
  public func status(_ challenge: HolderSessionChallenge, now: UInt64) throws -> Data {
    try invoke(.status(session: challenge.intent.session.handle, challenge: challenge), now: now)
  }
  private func invoke(_ command: HolderSessionAgentCommand, now: UInt64) throws -> Data {
    try Task.checkCancellation()
    guard handle != 0 else { throw HolderSessionError.custodyLost }
    let request = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
    var input = try HolderSessionAgentWire.request(command, requestID: request)
    defer { input.resetBytes(in: 0..<input.count) }
    let result = input.withUnsafeBytes { castalia_holder_session_invoke(handle, $0.bindMemory(to: UInt8.self).baseAddress, input.count) }
    guard result != 0 else { stop(); throw HolderSessionError.custodyLost }
    defer { castalia_result_free(result) }
    let size = castalia_result_length(result)
    guard size > 0, size <= 131072 else { stop(); throw HolderSessionError.invalid }
    var output = Data(count: size)
    defer { output.resetBytes(in: 0..<output.count) }
    let count = output.withUnsafeMutableBytes { castalia_result_copy(result, $0.bindMemory(to: UInt8.self).baseAddress, size) }
    guard count == size else { stop(); throw HolderSessionError.invalid }
    return try HolderSessionAgentWire.response(output, requestID: request, command: command, profile: profile, now: UInt64(Date().timeIntervalSince1970))
  }
}
