import Foundation

/// Application protocol selected by the exact, Wallet-approved disclosure.
/// The shared signed credential and presentation formats remain unchanged.
public enum WorkReadProtocol: String, Codable, Sendable {
  case nativeV2 = "devgraph.native-read-scope.v2"
  case monitorV3 = "devgraph.native-read-scope.v3"
  case pathV4 = "devgraph.native-read-scope.v4"
  case arenaV5 = "devgraph.native-read-scope.v5"
  case collectionArenaV6 = "devgraph.native-read-scope.v6"

  var supportsArena: Bool { self == .arenaV5 || self == .collectionArenaV6 }

  var operations: Set<String> {
    self == .nativeV2 ? ["list", "get"] : ["list", "get", "relationships"]
  }
  var workKinds: Set<String> {
    let original: Set<String> = ["Proposal", "Initiative", "Project", "Issue", "Task"]
    return self == .nativeV2 ? original : original.union(["Todo"])
  }
  var resultSchema: String {
    self == .nativeV2 ? "devgraph.native-read-result.v2" : self == .monitorV3 ? "devgraph.native-read-result.v3" : self == .pathV4 ? "devgraph.native-read-result.v4" : self == .arenaV5 ? "devgraph.native-read-result.v5" : "devgraph.native-read-result.v6"
  }
  var requestPath: String {
    self == .nativeV2 ? "/devgraph/native-read/v2/requests" : "/monitor/wallet-access/v1/requests"
  }
}

public struct WorkPageCursor: Sendable, Equatable {
  public let after: String
  public let revision: String?
}

public struct WorkPage: Sendable {
  public let items: [WorkRecord]
  public let next: WorkPageCursor?
}

func validWorkID(_ value: String) -> Bool {
  value.range(of: "^[a-z0-9](?:[a-z0-9-]{0,254}[a-z0-9])?$", options: .regularExpression) != nil
}

/// Canonical Todo pagination carries a snapshot revision and an opaque resource
/// cursor. It is priority ordered, so the old last-ID cursor cannot be reused.
func decodeMonitorPage(_ data: Data, kind: String, after: WorkPageCursor?) throws -> WorkPage {
  struct Page: Decodable {
    let schema: String
    let revision: String
    let items: [WorkRecord]
    let next_cursor: String?
    let complete: Bool
  }
  let page = try JSONDecoder().decode(Page.self, from: data)
  guard page.schema == "devgraph.todos.v2", page.complete,
    page.revision.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
    page.items.count <= 20, Set(page.items.map(\.rowID)).count == page.items.count,
    page.items.allSatisfy({ $0.kind == kind }),
    after.map({ $0.revision == page.revision }) ?? true
  else { throw WalletFailure.core("invalid_response") }
  if let cursor = page.next_cursor {
    guard !page.items.isEmpty, cursor == page.items.last?.rowID, cursor != after?.after else {
      throw WalletFailure.core("invalid_response")
    }
  }
  return WorkPage(
    items: page.items,
    next: page.next_cursor.map { WorkPageCursor(after: $0, revision: page.revision) })
}
