import Foundation
import ZenithKit

/// Invalidated immediately by the UI, even while expensive Rust work is running.
/// Only the short storage transaction holds this lock; cryptography never does.
final class LifecycleGate: @unchecked Sendable {
  private let mutex = NSLock()
  private var generation: UInt64 = 0
  func ticket() -> UInt64 {
    mutex.lock()
    defer { mutex.unlock() }
    return generation
  }
  func invalidate() {
    mutex.lock()
    generation &+= 1
    mutex.unlock()
  }
  func withCurrent<T>(_ ticket: UInt64, _ action: () throws -> T) throws -> T {
    mutex.lock()
    defer { mutex.unlock() }
    guard ticket == generation else { throw WalletFailure.locked }
    return try action()
  }
}
