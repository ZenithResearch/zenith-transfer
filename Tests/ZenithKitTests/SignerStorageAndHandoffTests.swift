import CastaliaSignerProtocol
import CastaliaSignerStorage
import CryptoKit
import Foundation
import SQLite3
import XCTest
import CastaliaSignerTransport

final class SignerStorageAndHandoffTests: XCTestCase {
  private let clientSigning = Curve25519.Signing.PrivateKey()
  private let clientAgreement = Curve25519.KeyAgreement.PrivateKey()
  private let signerSigning = Curve25519.Signing.PrivateKey()
  private let signerAgreement = Curve25519.KeyAgreement.PrivateKey()
  private var client: SignerPeer { try! SignerPeer(signingKey: SignerWire.hex(clientSigning.publicKey.rawRepresentation), agreementKey: SignerWire.hex(clientAgreement.publicKey.rawRepresentation)) }
  private var signer: SignerPeer { try! SignerPeer(signingKey: SignerWire.hex(signerSigning.publicKey.rawRepresentation), agreementKey: SignerWire.hex(signerAgreement.publicKey.rawRepresentation)) }
  private func request() throws -> SignedSignerRequest {
    try SignedSignerRequest(body: SignerRequestBody(clientKey: client.signingKey,
      expectedWallet: String(repeating: "a", count: 64), issuedAt: 100, expiresAt: 200,
      nonce: String(repeating: "b", count: 64), operation: .status), key: clientSigning)
  }
  func testEncryptedRequestAndResponseRequirePairedKeysAndOriginalSignedMessage() throws {
    let request = try request()
    let envelope = try SignerSealedHandoff(requestID: request.body.requestID, direction: .request,
      sender: client, recipient: signer, privateKey: clientAgreement, plaintext: request.encoded())
    let wire = try envelope.encoded()
    XCTAssertFalse(String(decoding: wire, as: UTF8.self).contains("expectedWallet"))
    let decoded = try SignerSealedHandoff.decode(wire)
    XCTAssertEqual(try decoded.openRequest(signer: signer, pairedClient: client, privateKey: signerAgreement, now: 101), request)
    XCTAssertThrowsError(try decoded.openRequest(signer: signer, pairedClient: client, privateKey: Curve25519.KeyAgreement.PrivateKey(), now: 101))
    XCTAssertThrowsError(try decoded.openRequest(signer: client, pairedClient: signer, privateKey: clientAgreement, now: 101))
    let response = try SignedSignerResponse(body: SignerResponseBody(request: request, signerKey: signer.signingKey,
      walletKey: request.body.expectedWallet, result: .state, expiresAt: 200, payload: Data("public state".utf8)), key: signerSigning)
    let reply = try SignerSealedHandoff(requestID: request.body.requestID, direction: .response, sender: signer,
      recipient: client, privateKey: signerAgreement, plaintext: response.encoded())
    XCTAssertEqual(try reply.openResponse(request: request, signer: signer, client: client, privateKey: clientAgreement, now: 101), response)
    XCTAssertThrowsError(try reply.openResponse(request: self.request(), signer: signer, client: client, privateKey: clientAgreement, now: 101))
  }
  func testEnvelopeSubstitutionTamperingExtraFieldsAndUnsignedPayloadFailClosed() throws {
    let request = try request()
    let original = try SignerSealedHandoff(requestID: request.body.requestID, direction: .request,
      sender: client, recipient: signer, privateKey: clientAgreement, plaintext: request.encoded())
    var raw = try XCTUnwrap(JSONSerialization.jsonObject(with: original.encoded()) as? [String: Any])
    raw["requestID"] = UUID().uuidString.lowercased()
    let changed = try SignerSealedHandoff.decode(JSONSerialization.data(withJSONObject: raw))
    XCTAssertThrowsError(try changed.openRequest(signer: signer, pairedClient: client, privateKey: signerAgreement, now: 101))
    raw["privateKey"] = "forbidden"
    XCTAssertThrowsError(try SignerSealedHandoff.decode(JSONSerialization.data(withJSONObject: raw)))
    let unsigned = try SignerSealedHandoff(requestID: request.body.requestID, direction: .request,
      sender: client, recipient: signer, privateKey: clientAgreement, plaintext: Data("{}".utf8))
    XCTAssertThrowsError(try unsigned.openRequest(signer: signer, pairedClient: client, privateKey: signerAgreement, now: 101))
    XCTAssertThrowsError(try SignerSealedHandoff(requestID: request.body.requestID, direction: .request,
      sender: client, recipient: signer, privateKey: clientAgreement, plaintext: Data(repeating: 0, count: 786_433)))
  }
  func testForegroundURLsContainCiphertextOnlyAndRefuseAlternateCallbacks() throws {
    let request = try request()
    let envelope = try SignerSealedHandoff(requestID: request.body.requestID, direction: .request,
      sender: client, recipient: signer, privateKey: clientAgreement, plaintext: request.encoded())
    let url = try SignerHandoffURL.request(envelope)
    XCTAssertFalse(url.absoluteString.contains(request.body.expectedWallet!))
    let decoded = try SignerHandoffURL.decode(url, expectedScheme: "castalia-signer", direction: .request)
    XCTAssertEqual(try decoded.openRequest(signer: signer, pairedClient: client, privateKey: signerAgreement, now: 101), request)
    XCTAssertThrowsError(try SignerHandoffURL.decode(URL(string: url.absoluteString + "&message=duplicate")!, expectedScheme: "castalia-signer", direction: .request))
    XCTAssertThrowsError(try SignerHandoffURL.decode(URL(string: url.absoluteString + "#fragment")!, expectedScheme: "castalia-signer", direction: .request))
    XCTAssertThrowsError(try SignerHandoffURL.response(envelope, clientScheme: "unpaired-app"))
    let large = try SignerSealedHandoff(requestID: request.body.requestID, direction: .request,
      sender: client, recipient: signer, privateKey: clientAgreement, plaintext: Data(repeating: 1, count: 16_384))
    XCTAssertThrowsError(try SignerHandoffURL.request(large))
  }
  #if os(macOS)
  func testXPCIdentityCannotUseUnsignedWildcardOrInjectedRequirement() throws {
    let identity = try SignerCodeIdentity(team: "EXAMPLE123", bundle: "ca.example.signer")
    XCTAssertTrue(identity.requirement.hasPrefix("anchor apple generic"))
    XCTAssertThrowsError(try SignerCodeIdentity(team: "-", bundle: "ca.example.signer"))
    XCTAssertThrowsError(try SignerCodeIdentity(team: "EXAMPLE123", bundle: "ca.example.signer\" or true"))
    XCTAssertThrowsError(try SignerCodeIdentity(team: "EXAMPLE123", bundle: "*"))
  }
  #endif
  private func temporaryDirectory() throws -> URL {
    let path = FileManager.default.temporaryDirectory.appendingPathComponent("signer-fixture-" + UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(at: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    addTeardownBlock { try? FileManager.default.removeItem(at: path) }; return path
  }
  func testEncryptedJournalPersistsAndCrossInstanceCASRejectsStaleWriter() throws {
    let folder = try temporaryDirectory(), key = SymmetricKey(size: .bits256)
    let first = try EncryptedSignerJournal(directory: folder, key: key)
    let second = try EncryptedSignerJournal(directory: folder, key: key)
    XCTAssertNil(try first.load())
    var snapshot = SignerJournalSnapshot(); snapshot.revision = 1; snapshot.epoch = 12
    try first.save(snapshot, expectedRevision: 0)
    XCTAssertEqual(try second.load(), snapshot)
    XCTAssertThrowsError(try second.save(snapshot, expectedRevision: 0))
    let wrongKey = try EncryptedSignerJournal(directory: folder, key: SymmetricKey(size: .bits256))
    XCTAssertThrowsError(try wrongKey.load())
    let bytes = try Data(contentsOf: folder.appendingPathComponent("consent.sqlite"))
    XCTAssertNil(bytes.range(of: Data("castalia.signer-journal.v1".utf8)))
  }
  func testJournalCannotOpenSymlinkOrOverlyAccessibleDirectory() throws {
    let root = try temporaryDirectory(), key = SymmetricKey(size: .bits256)
    let target = root.appendingPathComponent("outside"); try Data("preserve".utf8).write(to: target)
    try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("consent.sqlite"), withDestinationURL: target)
    XCTAssertThrowsError(try EncryptedSignerJournal(directory: root, key: key))
    XCTAssertEqual(try Data(contentsOf: target), Data("preserve".utf8))
    try FileManager.default.removeItem(at: root.appendingPathComponent("consent.sqlite"))
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: root.path)
    XCTAssertThrowsError(try EncryptedSignerJournal(directory: root, key: key))
  }
  func testJournalRowRevisionTamperingDoesNotRestoreConsent() throws {
    let folder = try temporaryDirectory(), key = SymmetricKey(size: .bits256)
    let store = try EncryptedSignerJournal(directory: folder, key: key)
    var snapshot = SignerJournalSnapshot(); snapshot.revision = 1
    try store.save(snapshot, expectedRevision: 0)
    var db: OpaquePointer?
    XCTAssertEqual(sqlite3_open(folder.appendingPathComponent("consent.sqlite").path, &db), SQLITE_OK)
    defer { sqlite3_close(db) }
    XCTAssertEqual(sqlite3_exec(db, "UPDATE consent SET revision=2", nil, nil, nil), SQLITE_OK)
    XCTAssertThrowsError(try store.load())
  }
}
