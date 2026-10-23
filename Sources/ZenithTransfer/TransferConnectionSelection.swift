#if os(macOS)
import CryptoKit
import Foundation
import ZenithKit

/// The chooser's namespaces are explicit. A missing selection never falls back
/// to a local service, a saved connection, or the first item in another list.
enum TransferConnectionSelection: Equatable {
  case local(String)
  case service(String)
  case saved(String)

  func localResource(in values: [LocalResource]) -> LocalResource? {
    guard case .local(let id) = self else { return nil }
    let matches = values.filter { $0.id == id }
    return matches.count == 1 ? matches[0] : nil
  }
  func service(in values: [LocalService]) -> LocalService? {
    guard case .service(let id)=self else { return nil }
    let matches=values.filter { $0.id==id }
    return matches.count==1 ? matches[0] : nil
  }
  func accessResource(in values: [LocalService], health: [String:LocalServiceHealth]) -> RegisteredResource? {
    guard let selected=service(in:values),selected.interface == .walletAPI,
      health["service:"+selected.id]?.walletAdministration == true,
      let configuration=selected.connection,configuration.origin==selected.endpoint else { return nil }
    return try? RegisteredResource(configuration:configuration)
  }
  func savedResource(in values: [RegisteredResource]) -> RegisteredResource? {
    guard case .saved(let id) = self else { return nil }
    let matches = values.filter { $0.id == id }
    return matches.count == 1 ? matches[0] : nil
  }
}

/// Capture the exact connection when opening the second screen. Its SwiftUI
/// identity includes the verification settings, so StateObjects cannot retain
/// another server's client, issuer pin or pending action after a new selection.
enum TransferConnectionScreen: Identifiable {
  case access(RegisteredResource)

  var endpoint: String {
    switch self {
    case .access(let resource): return resource.configuration.origin
    }
  }
  var id: String {
    let raw: Data
    let prefix: String
    switch self {
    case .access(let resource):
      prefix = "access:"
      let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
      // RegisteredResource's initializer already validates this public shape.
      raw = (try? encoder.encode(resource.configuration)) ?? Data(resource.id.utf8)
    }
    return prefix + SHA256.hash(data: raw).map { String(format: "%02x", $0) }.joined()
  }
}
#endif
