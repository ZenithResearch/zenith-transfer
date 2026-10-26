import Foundation

/// A startup hint, never evidence of Tailnet admission. The SDK validates the
/// state and its live control-plane status. Do not read or copy node-key bytes.
public enum TailscaleSavedState {
  public static func exists(in directory: URL) throws -> Bool {
    let manager = FileManager.default
    do {
      let parent = try manager.attributesOfItem(atPath: directory.path)
      guard parent[.type] as? FileAttributeType == .typeDirectory else {
        throw PrivateNetworkError.invalidStatus
      }
      let state = try manager.attributesOfItem(
        atPath: directory.appendingPathComponent("tailscaled.state").path)
      guard state[.type] as? FileAttributeType == .typeRegular else {
        throw PrivateNetworkError.invalidStatus
      }
      return ((state[.size] as? NSNumber)?.uint64Value ?? 0) > 0
    } catch let error as CocoaError where error.code == .fileReadNoSuchFile { return false }
  }
}
