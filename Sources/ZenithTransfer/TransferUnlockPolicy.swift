#if os(macOS)
import Foundation
import ZenithKit

typealias TransferUnlockDuration = WalletUnlockDuration
typealias TransferUnlockTimer = WalletUnlockTimer

extension WalletUnlockDuration {
  // Keep the existing macOS preference key; do not reset a saved choice.
  static let settingKey = "Transfer.wallet.unlockDurationSeconds.v1"
  static func load(_ defaults: UserDefaults) -> Self { load(defaults, key: settingKey) }
}
#endif
