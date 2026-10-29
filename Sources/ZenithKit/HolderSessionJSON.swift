import Foundation

struct HolderSessionJSON {
  let bytes: [UInt8]; var cursor = 0
  let maximumBytes: Int, maximumKeys: Int, maximumArray: Int, maximumDepth: Int
  let allowNegativeIntegers: Bool
  init(_ data: Data, maximumBytes: Int = 65536, maximumKeys: Int = 20, maximumArray: Int = 64, maximumDepth: Int = 8, allowNegativeIntegers: Bool = false) {
    bytes = Array(data); self.maximumBytes = maximumBytes; self.maximumKeys = maximumKeys
    self.maximumArray = maximumArray; self.maximumDepth = maximumDepth; self.allowNegativeIntegers = allowNegativeIntegers
  }
  mutating func space() { while cursor < bytes.count && [9,10,13,32].contains(bytes[cursor]) { cursor += 1 } }
  mutating func take(_ byte: UInt8) throws {
    space(); guard cursor < bytes.count, bytes[cursor] == byte else { throw HolderSessionError.invalid }; cursor += 1
  }
  mutating func string() throws -> String {
    space(); let start = cursor; try take(34); var escaped = false
    while cursor < bytes.count {
      let byte = bytes[cursor]; cursor += 1
      if escaped { escaped = false; continue }
      if byte == 92 { escaped = true; continue }
      if byte == 34 { return try JSONDecoder().decode(String.self, from: Data(bytes[start..<cursor])) }
    }
    throw HolderSessionError.invalid
  }
  mutating func value(_ depth: Int) throws {
    space(); guard depth <= maximumDepth, cursor < bytes.count else { throw HolderSessionError.invalid }
    switch bytes[cursor] {
    case 34: _ = try string()
    case 123:
      try take(123); space(); var keys: Set<String> = []
      if cursor < bytes.count && bytes[cursor] == 125 { cursor += 1; return }
      while true {
        let key = try string(); guard keys.insert(key).inserted, keys.count <= maximumKeys else { throw HolderSessionError.invalid }
        try take(58); try value(depth+1); space()
        guard cursor < bytes.count else { throw HolderSessionError.invalid }
        if bytes[cursor] == 125 { cursor += 1; break }; try take(44)
      }
    case 91:
      try take(91); space(); var count = 0
      if cursor < bytes.count && bytes[cursor] == 93 { cursor += 1; return }
      while true {
        count += 1; guard count <= maximumArray else { throw HolderSessionError.invalid }
        try value(depth+1); space(); guard cursor < bytes.count else { throw HolderSessionError.invalid }
        if bytes[cursor] == 93 { cursor += 1; break }; try take(44)
      }
    default:
      for literal in ["true", "false", "null"] {
        if bytes[cursor...].starts(with: Array(literal.utf8)) { cursor += literal.utf8.count; return }
      }
      let negative = allowNegativeIntegers && bytes[cursor] == 45
      if negative { cursor += 1 }
      let start = cursor
      while cursor < bytes.count && (48...57).contains(bytes[cursor]) { cursor += 1 }
      guard cursor > start, cursor - start == 1 || bytes[start] != 48,
        let value = UInt64(String(decoding: bytes[start..<cursor], as: UTF8.self)), value <= 9_007_199_254_740_991,
        !negative || value != 0 else { throw HolderSessionError.invalid }
    }
  }
  mutating func validate() throws {
    guard !bytes.isEmpty, bytes.count <= maximumBytes else { throw HolderSessionError.invalid }
    try value(0); space(); guard cursor == bytes.count else { throw HolderSessionError.invalid }
  }
}
