import CryptoKit
import Foundation

public enum RecoveryTransferError: Error, LocalizedError, Equatable {
  case invalidFile, tooLargeForQR, invalidQR, differentFile, damagedFile
  public var errorDescription: String? {
    switch self {
    case .invalidFile: return "Choose an encrypted recovery or Castaway file."
    case .tooLargeForQR: return "This file is too large for QR transfer. Use USB or Files instead."
    case .invalidQR: return "This is not a supported Zenith file QR."
    case .differentFile: return "A different file appeared. Cancel and scan one laptop file at a time."
    case .damagedFile: return "The file did not pass the transfer check. Scan it again or use USB."
    }
  }
}

/// Transport framing only. Rust still authenticates/decrypts the original bytes,
/// checks identity and evidence, and controls the final wallet commit.
public enum RecoveryQR {
  public static let maximumBytes = 65_536
  public static let chunkBytes = 720
  public static let maximumFrameCharacters = 1_100
  public static let prefix = "ZENITH-FILE:1"

  public static func frames(for data: Data) throws -> [String] {
    guard data.count <= maximumBytes else { throw RecoveryTransferError.tooLargeForQR }
    try EncryptedImportFile.validateEnvelope(data)
    let digest = hash(data)
    let count = (data.count + chunkBytes - 1) / chunkBytes
    return (0..<count).map { index in
      let start = index * chunkBytes
      let part = data.subdata(in: start..<min(start + chunkBytes, data.count))
      return "\(prefix):\(digest):\(data.count):\(index + 1):\(count):\(encode(part))"
    }
  }

  static func hash(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }
  static func encode(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
  }
  static func decode(_ value: String) -> Data? {
    guard !value.isEmpty,
      value.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0)
        || (48...57).contains($0) || $0 == 45 || $0 == 95 })
    else { return nil }
    var padded = value.replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    padded += String(repeating: "=", count: (4 - padded.count % 4) % 4)
    guard let result = Data(base64Encoded: padded), encode(result) == value else { return nil }
    return result
  }
}

public struct RecoveryQRProgress: Sendable {
  public let received: Int
  public let total: Int
  public let file: Data?
}

/// One bounded transfer at a time; duplicate and out-of-order frames are safe.
public struct RecoveryQRAssembler {
  private var digest: String?
  private var size = 0
  private var count = 0
  private var parts: [Int: Data] = [:]
  public init() {}
  public mutating func reset() { self = Self() }
  public mutating func accept(_ raw: String) throws -> RecoveryQRProgress {
    guard raw.utf8.count <= RecoveryQR.maximumFrameCharacters else {
      throw RecoveryTransferError.invalidQR
    }
    let fields = raw.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
    guard fields.count == 7, fields[0] == "ZENITH-FILE", fields[1] == "1",
      fields[2].utf8.count == 64,
      fields[2].utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
      let bytes = Int(fields[3]), (1...RecoveryQR.maximumBytes).contains(bytes),
      String(bytes) == fields[3], let index = Int(fields[4]), String(index) == fields[4],
      let total = Int(fields[5]), String(total) == fields[5],
      total == (bytes + RecoveryQR.chunkBytes - 1) / RecoveryQR.chunkBytes,
      (1...total).contains(index), let part = RecoveryQR.decode(fields[6]),
      part.count == (index == total ? bytes - (total - 1) * RecoveryQR.chunkBytes : RecoveryQR.chunkBytes)
    else { throw RecoveryTransferError.invalidQR }
    if let digest {
      guard digest == fields[2], size == bytes, count == total else {
        throw RecoveryTransferError.differentFile
      }
    } else {
      digest = fields[2]
      size = bytes
      count = total
    }
    if let existing = parts[index], existing != part {
      reset()
      throw RecoveryTransferError.damagedFile
    }
    parts[index] = part
    guard parts.count == total else {
      return RecoveryQRProgress(received: parts.count, total: total, file: nil)
    }
    var result = Data(capacity: size)
    for number in 1...count { result.append(parts[number]!) }
    guard result.count == size, RecoveryQR.hash(result) == digest else {
      reset()
      throw RecoveryTransferError.damagedFile
    }
    do { try EncryptedImportFile.validateEnvelope(result) } catch {
      reset()
      throw error
    }
    reset()
    return RecoveryQRProgress(received: total, total: total, file: result)
  }
}
