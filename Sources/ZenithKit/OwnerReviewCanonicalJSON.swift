#if os(macOS)
import CoreFoundation
import Foundation

/// Match DevGraph's canonical_json: UTF-8, code-point-sorted object keys,
/// compact separators and integer-only numbers. Foundation's .sortedKeys uses
/// collation rules that reorder punctuation/numeric filenames in inventories.
enum OwnerReviewCanonicalJSON {
  static func encode(_ value: Any) throws -> Data {
    Data(try string(value).utf8)
  }
  private static func quoted(_ value: String) throws -> String {
    let bytes = try JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed, .withoutEscapingSlashes])
    guard let text = String(data: bytes, encoding: .utf8) else { throw OwnerSetupError.invalid }
    return text
  }
  private static func string(_ value: Any) throws -> String {
    if let object = value as? [String: Any] {
      let keys = object.keys.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
      return "{" + (try keys.map { try quoted($0) + ":" + string(object[$0]!) }).joined(separator: ",") + "}"
    }
    if let array = value as? [Any] { return "[" + (try array.map(string)).joined(separator: ",") + "]" }
    if let text = value as? String { return try quoted(text) }
    if value is NSNull { return "null" }
    if let number = value as? NSNumber {
      if CFGetTypeID(number) == CFBooleanGetTypeID() { return number.boolValue ? "true" : "false" }
      guard !["f", "d"].contains(String(cString: number.objCType)) else { throw OwnerSetupError.invalid }
      return number.stringValue
    }
    throw OwnerSetupError.invalid
  }
}
#endif
