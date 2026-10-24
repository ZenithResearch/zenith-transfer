#if os(macOS)
import Foundation
import XCTest
import ZenithKit
@testable import ZenithTransfer

final class NativeSelectionPreflightTests: XCTestCase {
  /// Explicit opt-in offline diagnosis. Reads an existing inbox snapshot and
  /// emits selection JSON only; never creates a client, posts, or signs.
  func testOfflineReadSelectionWhenExplicitlyRequested() throws {
    let env = ProcessInfo.processInfo.environment
    guard let input = env["TRANSFER_PREFLIGHT_INBOX"], let output = env["TRANSFER_PREFLIGHT_OUTPUT"],
      let anchor = env["TRANSFER_PREFLIGHT_ANCHOR"] else { throw XCTSkip("No offline inbox preflight requested") }
    let raw = try GrantJSON.object(Data(contentsOf: URL(fileURLWithPath: input)))
    let ceiling = try XCTUnwrap(raw["ceiling"] as? [String: Any])
    let endpoint = try XCTUnwrap(ceiling["receiver"] as? String)
    let config = try WorkAccessConfiguration(name: "Offline preflight", receiver: XCTUnwrap(URL(string: endpoint)),
      issuer: XCTUnwrap(ceiling["issuer"] as? String), keyID: "offline-unused", publicKey: String(repeating: "12", count: 32))
    let inbox = try NativeOperatorInbox(raw, resource: RegisteredResource(configuration: config))
    XCTAssertEqual(inbox.requests.count, 1)
    let recipient = try XCTUnwrap(inbox.requests.first)
    let scope = try XCTUnwrap(inbox.scopes.first { $0.resource_path.path == [anchor] })
    var choice = NativeGrantChoice()
    choice.kinds = Set(inbox.permissions.kinds).intersection(["Initiative", "Project", "Issue", "Task", "Todo", "Proposal"])
    choice.reads = Set(["get", "list", "relationships"]).intersection(inbox.permissions.reads)
    choice.paths = [scope.resource_path]; choice.untilRevoked = true
    let selection = try NativeGrantSelection.make(ceiling: inbox.ceiling, ceilingDigest: inbox.digest,
      recipient: recipient, choice: choice, scopes: inbox.scopes, now: Int(Date().timeIntervalSince1970))
    let action: [String: Any] = ["schema": try XCTUnwrap(inbox.actionSchema(writes: false)), "action": "review",
      "action_id": UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(),
      "request_id": recipient.id, "request_digest_sha256": recipient.digest, "expected_version": recipient.version,
      "previous_assignment_digest": recipient.raw["previous_assignment_digest"] ?? NSNull(), "selection": selection]
    let file = URL(fileURLWithPath: output)
    try GrantJSON.data(action).write(to: file, options: .withoutOverwriting)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
  }
}
#endif
