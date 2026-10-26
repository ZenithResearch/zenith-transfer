@testable import CastaliaCustody
import Foundation
import Vision
import XCTest

@testable import ZenithKit

final class RecoveryTransferTests: XCTestCase {
  struct Vector: Decodable {
    let name: String
    let fileBase64: String
    let sha256: String
    let frames: [String]
    var file: Data { Data(base64Encoded: fileBase64)! }
  }
  private func vectors() throws -> [Vector] {
    struct File: Decodable { let cases: [Vector] }
    let url = Bundle.module.url(forResource: "qr-file-v1", withExtension: "json")!
    return try JSONDecoder().decode(File.self, from: Data(contentsOf: url)).cases
  }
  func testHistoricalCrossImplementationVectorsAndOutOfOrderAssembly() throws {
    for vector in try vectors() {
      XCTAssertEqual(try RecoveryQR.frames(for: vector.file), vector.frames)
      var scanner = RecoveryQRAssembler()
      var completed: Data?
      for frame in vector.frames.reversed() {
        let progress = try scanner.accept(frame)
        completed = progress.file ?? completed
        if progress.file == nil {
          let duplicate = try scanner.accept(frame)
          XCTAssertEqual(duplicate.received, progress.received)
        }
      }
      XCTAssertEqual(completed, vector.file)
      XCTAssertEqual(RecoveryQR.hash(completed!), vector.sha256)
    }
  }
  func testRenderedQRActuallyDecodesWithAppleVision() throws {
    for vector in try vectors() {
      for frame in vector.frames {
        let image = try RecoveryQRImage.render(frame)
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        try VNImageRequestHandler(cgImage: image).perform([request])
        XCTAssertEqual(request.results?.first?.payloadStringValue, frame)
      }
    }
  }
  func testMixedTransfersAndConflictingDuplicatesCannotComplete() throws {
    let all = try vectors()
    var scanner = RecoveryQRAssembler()
    XCTAssertNil(try scanner.accept(all[1].frames[0]).file)
    XCTAssertThrowsError(try scanner.accept(all[0].frames[0])) {
      XCTAssertEqual($0 as? RecoveryTransferError, .differentFile)
    }
    var fields = all[1].frames[0].components(separatedBy: ":")
    var part = RecoveryQR.decode(fields[6])!
    part[0] ^= 1
    fields[6] = RecoveryQR.encode(part)
    XCTAssertThrowsError(try scanner.accept(fields.joined(separator: ":"))) {
      XCTAssertEqual($0 as? RecoveryTransferError, .damagedFile)
    }
    // A cancelled/damaged transfer has no durable state and can start over.
    scanner.reset()
    XCTAssertEqual(try scanner.accept(all[0].frames[0]).file, all[0].file)
  }
  func testTamperingMalformedAndOversizedFramesFailClosed() throws {
    let frame = try vectors()[0].frames[0]
    var fields = frame.components(separatedBy: ":")
    var part = RecoveryQR.decode(fields[6])!
    part[part.count - 1] ^= 1
    fields[6] = RecoveryQR.encode(part)
    var scanner = RecoveryQRAssembler()
    XCTAssertThrowsError(try scanner.accept(fields.joined(separator: ":"))) {
      XCTAssertEqual($0 as? RecoveryTransferError, .damagedFile)
    }
    for raw in ["https://example.test/key", "ZENITH-FILE:2", String(repeating: "A", count: 1_101),
      frame + "=", frame.replacingOccurrences(of: ":713:", with: ":999999999999999999999:")]
    {
      XCTAssertThrowsError(try scanner.accept(raw))
    }
    var wrongCount = frame.components(separatedBy: ":")
    wrongCount[5] = "92"
    XCTAssertThrowsError(try scanner.accept(wrongCount.joined(separator: ":")))
  }
  func testQRLimitKeepsUSBOneMiBLimitAndRejectsPlaintext() throws {
    let file = try vectors()[0].file
    var atLimit = file
    atLimit.append(Data(repeating: 32, count: RecoveryQR.maximumBytes - file.count))
    let frames = try RecoveryQR.frames(for: atLimit)
    XCTAssertEqual(frames.count, 92)
    XCTAssertTrue(frames.allSatisfy { $0.count <= RecoveryQR.maximumFrameCharacters })
    var scanner = RecoveryQRAssembler()
    var result: Data?
    for frame in frames { result = try scanner.accept(frame).file }
    XCTAssertEqual(result, atLimit)
    atLimit.append(32)
    XCTAssertThrowsError(try RecoveryQR.frames(for: atLimit)) {
      XCTAssertEqual($0 as? RecoveryTransferError, .tooLargeForQR)
    }
    XCTAssertNoThrow(try EncryptedImportFile.validateEnvelope(atLimit))
    XCTAssertThrowsError(try EncryptedImportFile.validateEnvelope(Data(repeating: 32, count: 1_048_577)))
    XCTAssertThrowsError(try EncryptedImportFile.validateEnvelope(Data("raw recovery key".utf8)))
    var value = try JSONSerialization.jsonObject(with: file) as! [String: Any]
    value["privateKey"] = "must not be transferred"
    XCTAssertThrowsError(try RecoveryQR.frames(for: JSONSerialization.data(withJSONObject: value)))
  }
  func testUSBReadPreservesSourceRejectsLinksAndIgnoresFileExtension() throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let file = try vectors()[0].file
    let url = dir.appendingPathComponent("renamed-backup.bin")
    try file.write(to: url)
    let link = dir.appendingPathComponent("link.castalia-recovery")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: url)
    XCTAssertEqual(try EncryptedImportFile.read(url), file)
    XCTAssertEqual(try Data(contentsOf: url), file)
    XCTAssertThrowsError(try EncryptedImportFile.read(link))
    XCTAssertEqual(try USBImportInbox.files(in: dir).map { $0.resolvingSymlinksInPath() }, [url.resolvingSymlinksInPath()])
    XCTAssertThrowsError(try EncryptedImportFile.read(URL(string: "https://example.test/backup")!))
  }
  func testTransferredFileRestoresThroughUnchangedRustCoreOnlyAfterCommit() async throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: dir) }
    let original = try WalletRepository(directory: dir.appendingPathComponent("original"))
    let created = try await original.create(password: "disposable local password")
    let backup = try await original.exportRecovery(password: "disposable backup password")
    let frames = try RecoveryQR.frames(for: backup)
    var scanner = RecoveryQRAssembler()
    var received: Data?
    for frame in frames { received = try scanner.accept(frame).file }
    let restored = try WalletRepository(directory: dir.appendingPathComponent("restored"))
    do {
      _ = try await restored.prepareRestore(file: received!, filePassword: "wrong", password: "new local password")
      XCTFail("Wrong backup password accepted")
    } catch {}
    let preview = try await restored.prepareRestore(
      file: received!, filePassword: "disposable backup password", password: "new local password")
    let before = try await restored.state()
    XCTAssertFalse(before.configured)
    XCTAssertEqual(preview.publicKey, created.publicKey)
    let after = try await restored.commit(preview)
    XCTAssertTrue(after.backupVerified)
    XCTAssertEqual(after.publicKey, created.publicKey)
    do {
      _ = try await restored.prepareRestore(file: received!, filePassword: "disposable backup password", password: "replacement password")
      XCTFail("Existing wallet replaced")
    } catch {}
  }

  func testRecoverySelectionRereadsContentsAndRejectsDataOrLinks() async throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: dir) }
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let url = dir.appendingPathComponent("old.castaway")
    let backup = try vectors()[0].file
    try backup.write(to: url)
    let discovered = RecoveryFileCatalog.inspect(url)
    XCTAssertEqual(discovered.format?.kind, .recovery)
    XCTAssertEqual(try RecoveryFileCatalog.readRecovery(url), backup)
    let wallet = try WalletRepository(directory: dir.appendingPathComponent("wallet"))
    _ = try await wallet.create(password: "disposable picker password")
    let data = try await wallet.exportData(password: "disposable export password")
    try data.write(to: url)
    XCTAssertThrowsError(try RecoveryFileCatalog.readRecovery(discovered.url), "Cached recovery row cannot import replaced data")
    try FileManager.default.removeItem(at: url)
    XCTAssertThrowsError(try RecoveryFileCatalog.readRecovery(discovered.url))
    let original = dir.appendingPathComponent("valid.castalia-recovery")
    try backup.write(to: original)
    try FileManager.default.createSymbolicLink(at: url, withDestinationURL: original)
    XCTAssertThrowsError(try RecoveryFileCatalog.readRecovery(url))
    XCTAssertEqual(try Data(contentsOf: original), backup)
  }

  func testCatalogDistinguishesDeprecatedFilenameFromSupportedFormat() throws {
    let file = try vectors()[0].file
    let current = try RecoveryFileFormat.inspect(file, filename: "wallet.castalia-recovery")
    XCTAssertEqual(current.kind, .recovery)
    XCTAssertEqual(current.schema, "castalia.wallet-custody.v1")
    XCTAssertEqual(current.version, "v1")
    XCTAssertFalse(current.legacyFilename)
    for name in ["old.castaway", "old.CASTALIA-WALLET"] {
      let legacy = try RecoveryFileFormat.inspect(file, filename: name)
      XCTAssertEqual(legacy.kind, .recovery)
      XCTAssertTrue(legacy.legacyFilename)
      XCTAssertEqual(legacy.schema, current.schema)
    }
  }

  func testCatalogReadsOnlyMatchingDirectFilesAndKeepsUnsupportedVersionsVisible() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: root) }
    let folders = RecoveryFileCatalog.defaultFolders(home: root)
    for folder in folders { try FileManager.default.createDirectory(at: folder.url, withIntermediateDirectories: true) }
    let file = try vectors()[0].file
    let download = folders[1].url.appendingPathComponent("valid.castalia-recovery")
    try file.write(to: download)
    try file.write(to: folders[1].url.appendingPathComponent("unrelated.json"))
    let nested = folders[1].url.appendingPathComponent("nested")
    try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
    try file.write(to: nested.appendingPathComponent("not-discovered.castaway"))
    try FileManager.default.createSymbolicLink(at: folders[1].url.appendingPathComponent("link.castaway"), withDestinationURL: download)
    var future = try JSONSerialization.jsonObject(with: file) as! [String: Any]
    future["schema"] = "castalia.wallet-custody.v99"
    try JSONSerialization.data(withJSONObject: future).write(to: folders[0].url.appendingPathComponent("future.castalia-recovery"))
    let sections = RecoveryFileCatalog.scan(folders)
    XCTAssertEqual(sections.map { $0.files.count }, [1, 1, 0])
    XCTAssertEqual(sections[0].files[0].declaredSchema, "castalia.wallet-custody.v99")
    XCTAssertNil(sections[0].files[0].format)
    XCTAssertFalse(sections[0].files[0].canShowQR)
    XCTAssertTrue(sections[1].files[0].canShowQR)
    XCTAssertEqual(try Data(contentsOf: download), file)
    // A valid filename cannot make injected authority into a supported envelope.
    future["schema"] = "castalia.wallet-custody.v1"
    future["privateKey"] = "forbidden"
    try JSONSerialization.data(withJSONObject: future).write(to: download)
    XCTAssertNil(RecoveryFileCatalog.inspect(download).format)
    XCTAssertThrowsError(try EncryptedImportFile.read(download))
  }

  func testCatalogRecognizesActualRustDataExportEvenWithMisleadingExtension() async throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: dir) }
    let wallet = try WalletRepository(directory: dir)
    _ = try await wallet.create(password: "disposable catalog password")
    let data = try await wallet.exportData(password: "disposable data password")
    for name in ["data.castaway", "misnamed.castalia-recovery"] {
      let format = try RecoveryFileFormat.inspect(data, filename: name)
      XCTAssertEqual(format.kind, .castaway)
      XCTAssertEqual(format.schema, "castalia.castaway.v1")
      XCTAssertEqual(format.contentsSchema, "castalia.castaway-contents.v1")
      XCTAssertFalse(format.legacyFilename)
    }
  }
}
