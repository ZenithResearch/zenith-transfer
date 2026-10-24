import Foundation

/// Stored only by the signer, after signer-owned pairing review. It is not
/// accepted from an application's request envelope.
public struct SignerClientPolicy: Codable, Equatable, Sendable {
  public let clientKey: String
  public let walletKey: String
  public let operations: Set<SignerOperation>
  public let services: Set<SignerService>
  public let revoked: Bool
  public init(clientKey: String, walletKey: String, operations: Set<SignerOperation>,
    services: Set<SignerService>, revoked: Bool = false) throws {
    guard SignerWire.hex(clientKey, bytes: 32), SignerWire.hex(walletKey, bytes: 32),
      operations.count <= SignerOperation.allCases.count, services.count <= 32 else { throw SignerFailure.invalidMessage }
    for service in services { try service.validate() }
    self.clientKey = clientKey; self.walletKey = walletKey; self.operations = operations
    self.services = services; self.revoked = revoked
  }
  public func authorize(_ request: SignedSignerRequest, now: UInt64) throws {
    try validate()
    try request.verify(now: now)
    guard !revoked, clientKey == request.body.clientKey, operations.contains(request.body.operation) else { throw SignerFailure.unpairedClient }
    if let expected = request.body.expectedWallet, walletKey != expected { throw SignerFailure.wrongWallet }
    if let service = request.body.service, !services.contains(service) { throw SignerFailure.unpairedClient }
  }
  public func validate() throws {
    guard SignerWire.hex(clientKey, bytes: 32), SignerWire.hex(walletKey, bytes: 32),
      operations.count <= SignerOperation.allCases.count, services.count <= 32 else { throw SignerFailure.invalidMessage }
    for service in services { try service.validate() }
  }
}
public struct SignerPairing: Codable, Equatable, Sendable {
  public let peer: SignerPeer
  public let label: String
  public let callbackScheme: String
  public let policy: SignerClientPolicy
  public init(peer: SignerPeer, label: String, callbackScheme: String, policy: SignerClientPolicy) throws {
    self.peer = peer; self.label = label; self.callbackScheme = callbackScheme; self.policy = policy
    try validate()
  }
  public func validate() throws {
    try policy.validate()
    guard peer.signingKey == policy.clientKey, SignerWire.hex(peer.agreementKey, bytes: 32),
      !label.isEmpty, label.utf8.count <= 80, !label.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
      ["zenith-wallet-client", "zenith-transfer-client"].contains(callbackScheme) else { throw SignerFailure.invalidMessage }
  }
}
public enum SignerDecisionPhase: String, Codable, Sendable {
  case pending, signing, approved, denied, cancelled, uncertain
}
public struct SignerJournalEntry: Codable, Equatable, Sendable {
  public let request: SignedSignerRequest
  public let requestDigest: String
  public let summary: Data
  public var phase: SignerDecisionPhase
  public var approvedProof: Data?
  public var approvalNonce: String?
}
public struct SignerJournalSnapshot: Codable, Equatable, Sendable {
  public let schema: String
  public var revision: UInt64
  public var epoch: UInt64
  public var entries: [String: SignerJournalEntry]
  public var pairings: [String: SignerPairing]
  public init() { schema = "castalia.signer-journal.v1"; revision = 0; epoch = 0; entries = [:]; pairings = [:] }
}
/// Implementations must encrypt at rest in signer-private storage, perform
/// compare-and-swap atomically, and refuse unexpected existing files. No app
/// client receives this storage interface or journal contents.
public protocol SignerJournalStore: Sendable {
  func load() throws -> SignerJournalSnapshot?
  func save(_ snapshot: SignerJournalSnapshot, expectedRevision: UInt64) throws
}
public struct SignerApprovalTicket: Equatable, Sendable {
  public let requestID: String
  public let requestDigest: String
  public let clientKey: String
  public let epoch: UInt64
  public let nonce: String
  fileprivate init(requestID: String, requestDigest: String, clientKey: String, epoch: UInt64, nonce: String) {
    self.requestID = requestID; self.requestDigest = requestDigest; self.clientKey = clientKey
    self.epoch = epoch; self.nonce = nonce
  }
}

/// Only signer-owned UI may call beginApproval/complete/decline. None of those
/// methods is part of the XPC or URL client interface. The native core still
/// verifies the original protocol, pins and one-use consent before signing.
public actor SignerConsentJournal {
  private var snapshot: SignerJournalSnapshot
  private let store: any SignerJournalStore
  public init(store: any SignerJournalStore) throws {
    self.store = store
    var loaded = try store.load() ?? SignerJournalSnapshot()
    guard loaded.schema == "castalia.signer-journal.v1", loaded.entries.count <= 256, loaded.pairings.count <= 16,
      loaded.revision < 9_007_199_254_740_991, loaded.epoch < 9_007_199_254_740_991 else { throw SignerFailure.invalidMessage }
    for (key, pairing) in loaded.pairings {
      try pairing.validate(); guard key == pairing.peer.signingKey else { throw SignerFailure.invalidMessage }
    }
    for (id, entry) in loaded.entries {
      try entry.request.verify(now: entry.request.body.issuedAt)
      guard id == entry.request.body.requestID, entry.requestDigest == (try entry.request.digest),
        entry.summary.count <= 262_144, (entry.approvedProof?.count ?? 0) <= 524_288,
        (entry.phase == .approved) == (entry.approvedProof?.isEmpty == false),
        (entry.phase == .signing) == (entry.approvalNonce.map(SignerWire.uuid) == true) else { throw SignerFailure.invalidMessage }
    }
    // A crash between dispatch and durable result is uncertain, never permission
    // to repeat the root operation. Pending UI reviews do not survive restart.
    var changed = false
    for (id, var entry) in loaded.entries {
      if entry.phase == .signing { entry.phase = .uncertain; entry.approvalNonce = nil; loaded.entries[id] = entry; changed = true }
      else if entry.phase == .pending { entry.phase = .cancelled; loaded.entries[id] = entry; changed = true }
    }
    if changed {
      let revision = loaded.revision; loaded.revision += 1; loaded.epoch += 1
      try store.save(loaded, expectedRevision: revision)
    }
    snapshot = loaded
  }
  private func persist(_ next: SignerJournalSnapshot) throws {
    guard snapshot.revision < 9_007_199_254_740_990 else { throw SignerFailure.invalidMessage }
    var next = next; next.revision = snapshot.revision + 1
    try store.save(next, expectedRevision: snapshot.revision)
    snapshot = next
  }
  /// Trusted signer-owned UI only. Pairing is never an exported IPC operation.
  /// Re-pairing a key must be reviewed against the current exact saved record.
  public func pair(_ value: SignerPairing, replacing expected: SignerPairing?) throws {
    try value.validate()
    guard snapshot.pairings[value.peer.signingKey] == expected,
      expected != nil || snapshot.pairings.count < 16 else { throw SignerFailure.changedRequest }
    var next = snapshot; next.pairings[value.peer.signingKey] = value
    for (id, var entry) in next.entries where entry.request.body.clientKey == value.peer.signingKey &&
      (entry.phase == .pending || entry.phase == .signing) {
      entry.phase = entry.phase == .signing ? .uncertain : .cancelled
      entry.approvalNonce = nil; next.entries[id] = entry
    }
    try persist(next)
  }
  public func pairing(clientKey: String) throws -> SignerPairing {
    guard let value = snapshot.pairings[clientKey], !value.policy.revoked else { throw SignerFailure.unpairedClient }
    try value.validate(); return value
  }
  public func pairings() -> [SignerPairing] { Array(snapshot.pairings.values) }
  public func register(_ request: SignedSignerRequest, policy: SignerClientPolicy,
    verifiedSummary: Data, now: UInt64) throws -> SignerJournalEntry {
    guard try pairing(clientKey: request.body.clientKey).policy == policy else { throw SignerFailure.unpairedClient }
    try policy.authorize(request, now: now)
    guard [.prepareServiceProof, .reviewWalletIdentities].contains(request.body.operation),
      !verifiedSummary.isEmpty, verifiedSummary.count <= 262_144 else { throw SignerFailure.invalidMessage }
    let digest = try request.digest
    if let original = snapshot.entries[request.body.requestID] {
      guard original.requestDigest == digest, original.request.body.clientKey == request.body.clientKey else { throw SignerFailure.changedRequest }
      return original
    }
    var base = snapshot
    base.entries = base.entries.filter { _, entry in
      entry.request.body.expiresAt > now || entry.phase == .signing || entry.phase == .uncertain
    }
    guard base.entries.count < 256 else { throw SignerFailure.unavailable }
    let entry = SignerJournalEntry(request: request, requestDigest: digest, summary: verifiedSummary,
      phase: .pending, approvedProof: nil, approvalNonce: nil)
    var next = base; next.entries[request.body.requestID] = entry; try persist(next); return entry
  }
  public func entry(requestID: String, clientKey: String) throws -> SignerJournalEntry {
    guard let entry = snapshot.entries[requestID], entry.request.body.clientKey == clientKey else { throw SignerFailure.unpairedClient }
    return entry
  }
  public func beginApproval(requestID: String, clientKey: String, reviewedDigest: String, policy: SignerClientPolicy, now: UInt64) throws -> SignerApprovalTicket {
    guard try pairing(clientKey: clientKey).policy == policy else { throw SignerFailure.unpairedClient }
    var entry = try entry(requestID: requestID, clientKey: clientKey)
    try policy.authorize(entry.request, now: now)
    guard entry.requestDigest == reviewedDigest else { throw SignerFailure.changedRequest }
    guard entry.phase == .pending else { throw entry.phase == .cancelled ? SignerFailure.cancelled : SignerFailure.alreadyDecided }
    let nonce = UUID().uuidString.lowercased()
    let ticket = SignerApprovalTicket(requestID: requestID, requestDigest: reviewedDigest, clientKey: clientKey,
      epoch: snapshot.epoch, nonce: nonce)
    entry.phase = .signing; entry.approvalNonce = nonce
    var next = snapshot; next.entries[requestID] = entry; try persist(next); return ticket
  }
  public func complete(_ ticket: SignerApprovalTicket, approvedProof: Data, policy: SignerClientPolicy, now: UInt64) throws {
    guard try pairing(clientKey: ticket.clientKey).policy == policy else { throw SignerFailure.unpairedClient }
    var entry = try entry(requestID: ticket.requestID, clientKey: ticket.clientKey)
    guard ticket.epoch == snapshot.epoch, entry.phase == .signing,
      entry.approvalNonce == ticket.nonce, entry.requestDigest == ticket.requestDigest,
      !approvedProof.isEmpty, approvedProof.count <= 524_288 else { throw SignerFailure.changedRequest }
    try policy.authorize(entry.request, now: now)
    entry.phase = .approved; entry.approvedProof = approvedProof; entry.approvalNonce = nil
    var next = snapshot; next.entries[ticket.requestID] = entry; try persist(next)
  }
  public func cancel(requestID: String, clientKey: String) throws {
    var entry = try entry(requestID: requestID, clientKey: clientKey)
    guard entry.phase == .pending || entry.phase == .signing else { throw SignerFailure.alreadyDecided }
    entry.phase = entry.phase == .signing ? .uncertain : .cancelled; entry.approvalNonce = nil
    var next = snapshot; next.entries[requestID] = entry; try persist(next)
  }
  public func decline(requestID: String, clientKey: String, reviewedDigest: String) throws {
    var entry = try entry(requestID: requestID, clientKey: clientKey)
    guard entry.requestDigest == reviewedDigest, entry.phase == .pending else { throw SignerFailure.changedRequest }
    entry.phase = .denied
    var next = snapshot; next.entries[requestID] = entry; try persist(next)
  }
  public func invalidatePending() throws {
    guard snapshot.epoch < 9_007_199_254_740_990 else { throw SignerFailure.invalidMessage }
    var next = snapshot; next.epoch += 1
    for (id, var entry) in next.entries where entry.phase == .pending || entry.phase == .signing {
      entry.phase = entry.phase == .signing ? .uncertain : .cancelled; entry.approvalNonce = nil; next.entries[id] = entry
    }
    try persist(next)
  }
}
