#if os(macOS)
import AppKit
import SwiftUI

/// Plaintext is rendered only on the user's explicit reveal action. Normal
/// native editing supports paste in both modes and selection/copy when shown.
struct TransferPasswordField: View {
  let title: String
  @Binding var text: String
  var submit: () -> Void = {}
  @State private var revealed = false
  var body: some View {
    VStack(alignment: .leading, spacing: 6) {
      Text(title).font(.callout.weight(.medium))
      HStack(spacing: 8) {
        Group {
          if revealed { TextField(title, text: $text) }
          else { SecureField(title, text: $text) }
        }.textFieldStyle(.roundedBorder).onSubmit(submit)
        Button { revealed.toggle() } label: {
          Image(systemName: revealed ? "eye.slash" : "eye")
        }.buttonStyle(.borderless)
          .accessibilityLabel(revealed ? "Hide \(title)" : "Show \(title)")
          .help(revealed ? "Hide password" : "Show password")
        if revealed {
          Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
          } label: { Image(systemName: "doc.on.doc") }
            .buttonStyle(.borderless).disabled(text.isEmpty)
            .accessibilityLabel("Copy \(title)")
            .help("Copy password to this Mac’s clipboard")
        }
      }
    }
    .onChange(of: text.isEmpty) { empty in if empty { revealed = false } }
    .onDisappear { revealed = false }
    .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in revealed = false }
  }
}

/// Mirrors Rust's Unicode-scalar minimum and UTF-8 byte ceiling. Do not trim or
/// normalize passwords; the recovery file may have a different historical rule.
enum TransferPasswordRules {
  static func permitsLocal(_ value: String) -> Bool {
    value.unicodeScalars.count >= 12 && value.utf8.count <= 4096
  }
  static func importPassword(file: String, local: String, confirmation: String, reuse: Bool) -> String? {
    let selected = reuse ? file : local
    guard !file.isEmpty, permitsLocal(selected), reuse || local == confirmation else { return nil }
    return selected
  }
}
#endif
