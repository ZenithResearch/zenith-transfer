#if os(macOS)
import Foundation
import XCTest
@testable import ZenithKit

final class OwnerReviewCanonicalJSONTests: XCTestCase {
  func testInventoryKeysMatchPythonRatherThanFoundationCollation() throws {
    let value: [String: Any] = ["source/v2.py": "two", "source/v10.py": "ten",
      "source/secs_work.py": "base", "source/secs_work_v2.py": "v2", "Z": false, "a": true]
    let expected = #"{"Z":false,"a":true,"source/secs_work.py":"base","source/secs_work_v2.py":"v2","source/v10.py":"ten","source/v2.py":"two"}"#
    XCTAssertEqual(String(decoding: try OwnerReviewCanonicalJSON.encode(value), as: UTF8.self), expected)
    XCTAssertNotEqual(try OwnerReviewCanonicalJSON.encode(value), try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .withoutEscapingSlashes]))
  }
  func testNestedStringsBooleansNullAndIntegersKeepCanonicalBytes() throws {
    let value: [String: Any] = ["z": [NSNull(), true, 0, 1792722956], "é": "line\n\"/é", "a": ["b": false]]
    let expected = "{\"a\":{\"b\":false},\"z\":[null,true,0,1792722956],\"é\":\"line\\n\\\"/é\"}"
    XCTAssertEqual(String(decoding: try OwnerReviewCanonicalJSON.encode(value), as: UTF8.self), expected)
    XCTAssertThrowsError(try OwnerReviewCanonicalJSON.encode(["value": 1.25]))
  }
}
#endif
