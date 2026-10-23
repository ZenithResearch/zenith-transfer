#if os(macOS)
import Foundation
import XCTest
@testable import ZenithKit

final class LocalResourceDiscoveryTests: XCTestCase {
  private struct Vector: Decodable { let name: String; let accepted: Bool; let raw: String }
  private func vectors() throws -> [Vector] {
    struct Document: Decodable { let cases: [Vector] }
    return try JSONDecoder().decode(Document.self, from: Data(contentsOf: Bundle.module.url(forResource: "zenith-local-resource-v1", withExtension: "json")!)).cases
  }
  private func fixture(_ name: String = "local-monitor-without-wallet") throws -> Data {
    Data(try XCTUnwrap(vectors().first { $0.name == name }).raw.utf8)
  }
  private func temporary() throws -> URL {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return home
  }
  private func registry(_ home: URL) throws -> URL {
    var directory = home
    for part in [".zenith", "resources", "v1"] {
      directory.appendPathComponent(part)
      try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }
    return directory
  }
  @discardableResult private func write(_ data: Data, in directory: URL) throws -> URL {
    let resource = try LocalResource.decode(data)
    let url = directory.appendingPathComponent(resource.id + ".json")
    try data.write(to: url, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    return url
  }
  func testSharedProducerConsumerVectors() throws {
    for vector in try vectors() {
      if vector.accepted { XCTAssertNoThrow(try LocalResource.decode(Data(vector.raw.utf8)), vector.name) }
      else { XCTAssertThrowsError(try LocalResource.decode(Data(vector.raw.utf8)), vector.name) }
    }
  }
  func testDiscoveryIsReadOnlyAndStableIDSurvivesChangedConnection() throws {
    let home = try temporary(); defer { try? FileManager.default.removeItem(at: home) }
    XCTAssertTrue(LocalResourceDiscovery.scan(home: home).resources.isEmpty)
    XCTAssertFalse(FileManager.default.fileExists(atPath: LocalResourceDiscovery.directory(home: home).path))
    let folder = try registry(home)
    let file = try write(fixture(), in: folder)
    let first = LocalResourceDiscovery.scan(home: home)
    XCTAssertEqual(first.resources.count, 1); XCTAssertFalse(first.unavailable)
    XCTAssertNil(first.resources[0].connection)
    XCTAssertEqual(first.resources[0].monitorURL.absoluteString, "http://127.0.0.1:8080/monitor/")
    try write(fixture("https-operator-profile"), in: folder)
    let refreshed = LocalResourceDiscovery.scan(home: home)
    XCTAssertEqual(refreshed.resources[0].id, first.resources[0].id)
    XCTAssertEqual(refreshed.resources[0].connection?.origin, "https://graph.example")
    XCTAssertEqual(try Data(contentsOf: file), try fixture("https-operator-profile"))
    XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: folder.path).count, 1)
  }
  func testInvalidRecordsDoNotHideValidServicesAndUnsafeDirectoriesFailClosed() throws {
    let home = try temporary(); defer { try? FileManager.default.removeItem(at: home) }
    let folder = try registry(home)
    let file = try write(fixture("pinned-lan-profile"), in: folder)
    let bad = folder.appendingPathComponent("not-a-resource.json")
    try Data("{\"credential\":\"not discovery\"}".utf8).write(to: bad)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: bad.path)
    var result = LocalResourceDiscovery.scan(home: home)
    XCTAssertEqual(result.resources.count, 1); XCTAssertEqual(result.rejected, 1)
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
    result = LocalResourceDiscovery.scan(home: home)
    XCTAssertTrue(result.resources.isEmpty); XCTAssertEqual(result.rejected, 2)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    let backup = home.appendingPathComponent("outside.json")
    try Data(contentsOf: file).write(to: backup)
    try FileManager.default.removeItem(at: file)
    try FileManager.default.createSymbolicLink(at: file, withDestinationURL: backup)
    XCTAssertTrue(LocalResourceDiscovery.scan(home: home).resources.isEmpty)
    // An owner-readable file outside the registry cannot enter through a link.
    let outside = home.appendingPathComponent("outside", isDirectory: true)
    try FileManager.default.moveItem(at: folder, to: outside)
    try FileManager.default.createSymbolicLink(at: folder, withDestinationURL: outside)
    XCTAssertTrue(LocalResourceDiscovery.scan(home: home).unavailable)
    XCTAssertTrue(FileManager.default.fileExists(atPath: backup.path))
  }
  func testRegistryLimitAndWrongFilenameAreNotAccepted() throws {
    let home = try temporary(); defer { try? FileManager.default.removeItem(at: home) }
    let folder = try registry(home)
    let source = try fixture()
    for index in 0..<101 {
      let url = folder.appendingPathComponent("\(index).json")
      try source.write(to: url)
      try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
    let overLimit = LocalResourceDiscovery.scan(home: home)
    XCTAssertTrue(overLimit.unavailable); XCTAssertTrue(overLimit.resources.isEmpty)
    for index in 1..<101 { try FileManager.default.removeItem(at: folder.appendingPathComponent("\(index).json")) }
    let mismatch = LocalResourceDiscovery.scan(home: home)
    XCTAssertEqual(mismatch.rejected, 1); XCTAssertTrue(mismatch.resources.isEmpty)
  }
}
#endif
