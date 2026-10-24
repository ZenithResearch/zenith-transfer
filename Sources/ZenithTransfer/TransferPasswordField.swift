#if os(macOS)
import SwiftUI
import ZenithKit

struct TransferPasswordField: View {
  let title: String
  @Binding var text: String
  var submit: () -> Void = {}
  var body: some View { WalletPasswordEntry(title: title, text: $text, submit: submit) }
}
typealias TransferPasswordRules = WalletPasswordRules
#endif
