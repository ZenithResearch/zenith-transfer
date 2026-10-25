import CryptoKit
import Foundation

public struct WorkAccessRequestRecord: Codable, Sendable, Equatable {
  public let receiver: String
  public let subject: String
  public let installation: String
  public let requestID: String
  public let preference: WorkAccessPreference?
}
/// Only public identifiers persist, so a lost response can be checked after
/// relaunch without submitting another request. No proof or credential is saved.
public final class WorkAccessRequestStore: @unchecked Sendable {
  private let directory: URL
  private let lock = NSLock()
  public init(directory: URL) throws {
    self.directory = directory
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    var path = directory; var values = URLResourceValues(); values.isExcludedFromBackup = true
    try path.setResourceValues(values)
  }
  private func file(_ receiver: String, _ subject: String, _ installation: String) -> URL {
    let key = SHA256.hash(data: Data((receiver + "\n" + subject + "\n" + installation).utf8)).map { String(format:"%02x",$0) }.joined()
    return directory.appendingPathComponent(key + ".json")
  }
  public func existing(receiver: String, subject: String, installation: String) throws -> WorkAccessRequestRecord? {
    lock.lock(); defer { lock.unlock() }
    return try load(receiver,subject,installation)
  }
  private func load(_ receiver: String, _ subject: String, _ installation: String) throws -> WorkAccessRequestRecord? {
    let path = file(receiver,subject,installation)
    guard FileManager.default.fileExists(atPath: path.path) else { return nil }
    let data = try Data(contentsOf: path)
    guard data.count <= 16_384 else { throw WalletFailure.invalidFile }
    let value = try JSONDecoder().decode(WorkAccessRequestRecord.self, from: data)
    guard value.receiver == receiver, value.subject == subject, value.installation == installation,
      value.requestID.range(of:"^[0-9a-f]{32}$", options:.regularExpression) != nil else { throw WalletFailure.invalidFile }
    return value
  }
  public func begin(receiver: String, subject: String, installation: String, preference: WorkAccessPreference? = nil, requestID: String? = nil) throws -> WorkAccessRequestRecord {
    lock.lock(); defer { lock.unlock() }
    if let old = try load(receiver,subject,installation) { return old }
    let identifier = requestID ?? UUID().uuidString.replacingOccurrences(of:"-",with:"").lowercased()
    guard identifier.range(of:"^[0-9a-f]{32}$",options:.regularExpression) != nil else { throw WalletFailure.invalidFile }
    let value = WorkAccessRequestRecord(receiver:receiver,subject:subject,installation:installation,requestID:identifier,preference:preference)
    let path = file(receiver,subject,installation)
    #if os(iOS)
    try JSONEncoder().encode(value).write(to:path,options:[.atomic,.completeFileProtection])
    #else
    try JSONEncoder().encode(value).write(to:path,options:.atomic)
    #endif
    try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:path.path)
    return value
  }
  public func startNew(receiver: String, subject: String, installation: String, after result: WorkAccessRequestResult) throws {
    lock.lock(); defer { lock.unlock() }
    guard let old = try load(receiver,subject,installation), old.requestID == result.request_id,
      ["active","denied","expired","revoked","superseded","partially_active"].contains(result.status),
      !result.authority_issued else { throw WalletFailure.core("recover_original_request_first") }
    let history = directory.appendingPathComponent("history", isDirectory:true)
    try FileManager.default.createDirectory(at:history,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
    let original = file(receiver,subject,installation), archive = history.appendingPathComponent(old.requestID+".json")
    let bytes = try Data(contentsOf:original)
    if FileManager.default.fileExists(atPath:archive.path) {
      guard try Data(contentsOf:archive) == bytes else { throw WalletFailure.invalidFile }
    } else {
      try bytes.write(to:archive,options:.atomic)
      try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:archive.path)
    }
    try FileManager.default.removeItem(at:original)
  }

}
public struct NativeAccessRequestPreview: Decodable, Sendable {
  package let token: String
  package let summary: Summary
  package struct Summary: Decodable, Sendable {
    package let issuer: String
    package let receiver: String
    package let operation: String
    package let expires_at: UInt64
  }
}
public struct WorkAccessRequestConsent: Sendable {
  public let requestID: String
  public let receiver: String
  public let issuer: String
  public let checkingStatus: Bool
  public let approvalExpires: Date
  public let preference: WorkAccessPreference?
  public let membershipRequirement: WorkMembershipRequirement
  let native: NativeAccessRequestPreview
  let lifecycle: UInt64
}
public struct WorkAccessRequestResult: Decodable, Sendable {
  public let schema: String
  public let request_id: String
  public let status: String
  public let authority_issued: Bool
  public let grant_active: Bool?
  public let read_active: Bool?
  public let write_active: Bool?
  public init(schema:String,request_id:String,status:String,authority_issued:Bool,grant_active:Bool?=nil,read_active:Bool?=nil,write_active:Bool?=nil) {
    self.schema=schema;self.request_id=request_id;self.status=status;self.authority_issued=authority_issued
    self.grant_active=grant_active;self.read_active=read_active;self.write_active=write_active
  }
}

public extension DevgraphReadClient {
  func hasAccessRequest(store: WorkAccessRequestStore) async throws -> Bool {
    let identity = try JSONSerialization.jsonObject(with: await repository.graphAccessIdentityV2()) as? [String:String]
    guard let owner=identity?["subject_public_key"],let device=identity?["installation_id"] else { throw WalletFailure.core("invalid_response") }
    return try store.existing(receiver:configuration.origin,subject:owner,installation:device) != nil
  }
  func startNewAccessRequest(store: WorkAccessRequestStore, after result: WorkAccessRequestResult) async throws {
    let identity = try JSONSerialization.jsonObject(with: await repository.graphAccessIdentityV2()) as? [String:String]
    guard let owner=identity?["subject_public_key"],let device=identity?["installation_id"] else { throw WalletFailure.core("invalid_response") }
    try store.startNew(receiver:configuration.origin,subject:owner,installation:device,after:result)
  }

  func prepareAccessRequest(store: WorkAccessRequestStore, resubmitOriginal: Bool = false, preference: WorkAccessPreference? = nil) async throws -> WorkAccessRequestConsent {
    let ticket = repository.lifecycleTicket()
    let requirement = try await membershipRequirement()
    let identity = try JSONSerialization.jsonObject(with: await repository.graphAccessIdentityV2()) as? [String:String]
    guard let owner = identity?["subject_public_key"], let device = identity?["installation_id"] else { throw WalletFailure.core("invalid_response") }
    let old = try store.existing(receiver:configuration.origin,subject:owner,installation:device)
    let record = old ?? WorkAccessRequestRecord(receiver:configuration.origin,subject:owner,installation:device,requestID:UUID().uuidString.replacingOccurrences(of:"-",with:"").lowercased(),preference:preference)
    let submitting = old == nil || resubmitOriginal
    let intent: Any
    if submitting, let preferred = record.preference {
      intent = ["schema":"devgraph.access-intent.v2","preference":try JSONSerialization.jsonObject(with:JSONEncoder().encode(preferred))]
    } else { intent = NSNull() }
    let action:[String:Any] = ["schema":record.preference == nil ? "devgraph.access-request-action.v1":"devgraph.access-request-action.v2","action":submitting ? "submit":"status","request_id":record.requestID,"subject_public_key":owner,"installation_id":device,"intent":intent]
    var request = URLRequest(url:URL(string:configuration.origin + "/devgraph/access-requests/v2/challenges")!)
    request.httpMethod="POST";request.httpBody=try JSONSerialization.data(withJSONObject:["request":action]);request.setValue("application/json",forHTTPHeaderField:"Content-Type")
    let challenge = try await transport.request(request,maximum:16_384)
    guard let value = try JSONSerialization.jsonObject(with:challenge) as? [String:Any],
      let details = value["details"] as? [String:Any], NSDictionary(dictionary:details).isEqual(to:action) else { throw WalletFailure.core("invalid_response") }
    try repository.checkLifecycle(ticket)
    let prepared = try await repository.prepareGraphAccessRequestV2(challenge,pin:configuration.authority,now:UInt64(Date().timeIntervalSince1970))
    try repository.checkLifecycle(ticket)
    // Persist before presenting consent. A server-rejected unsigned preparation
    // must not strand the member with a stale, unsubmitted catalog preference.
    let saved = try store.begin(receiver:configuration.origin,subject:owner,installation:device,preference:record.preference,requestID:record.requestID)
    guard saved == record else { throw WalletFailure.core("recover_original_request_first") }
    return WorkAccessRequestConsent(requestID:record.requestID,receiver:prepared.summary.receiver,issuer:prepared.summary.issuer,checkingStatus:old != nil && !resubmitOriginal,approvalExpires:Date(timeIntervalSince1970:Double(prepared.summary.expires_at)),preference:record.preference,membershipRequirement:requirement,native:prepared,lifecycle:ticket)
  }
  func submitAccessRequest(_ consent: WorkAccessRequestConsent) async throws -> WorkAccessRequestResult {
    try repository.checkLifecycle(consent.lifecycle)
    guard consent.receiver == configuration.origin, consent.issuer == configuration.issuer else { throw WalletFailure.core("invalid_response") }
    let approved = try consent.membershipRequirement.approvalBody(
      await repository.approveGraphAccessRequestV2(consent.native, now:UInt64(Date().timeIntervalSince1970),ticket:consent.lifecycle))
    var request=URLRequest(url:URL(string:configuration.origin + "/devgraph/access-requests/v2/actions")!)
    request.httpMethod="POST";request.httpBody=approved;request.setValue("application/json",forHTTPHeaderField:"Content-Type")
    // Never automatically repeat a submit after an uncertain response. The
    // persistent ID makes the next explicit preparation a status check.
    let data=try await transport.request(request,maximum:16_384)
    try repository.checkLifecycle(consent.lifecycle)
    let result=try JSONDecoder().decode(WorkAccessRequestResult.self,from:data)
    guard ["devgraph.access-request-result.v1","devgraph.access-request-result.v2","devgraph.access-request-result.v3","devgraph.access-request-result.v4"].contains(result.schema), result.request_id == consent.requestID, !result.authority_issued,
      ["pending","active","approved","approved_pending_activation","denied","declined","expired","revoked","unknown","superseded","partially_active"].contains(result.status) else { throw WalletFailure.core("invalid_response") }
    if ["devgraph.access-request-result.v3","devgraph.access-request-result.v4"].contains(result.schema) {
      guard result.grant_active == (result.status == "active") else { throw WalletFailure.core("invalid_response") }
    }
    if result.schema == "devgraph.access-request-result.v4" {
      guard let read = result.read_active, let write = result.write_active,
        result.grant_active == (read && write),
        (result.status == "partially_active") == (read != write)
      else { throw WalletFailure.core("invalid_response") }
    }
    return result
  }
}
