#if os(macOS)
import SwiftUI

/// Keep primary actions visible even when the system accent color is white.
struct TransferPrimaryButtonStyle: ButtonStyle {
  @Environment(\.isEnabled) private var enabled
  func makeBody(configuration: Configuration) -> some View {
    configuration.label
      .fontWeight(.semibold)
      .padding(.horizontal, 14).padding(.vertical, 7)
      .foregroundStyle(enabled ? Color.white : Color.secondary)
      .background(enabled ? Color(red: 0.06, green: 0.37, blue: 0.30).opacity(configuration.isPressed ? 0.8 : 1) : Color.primary.opacity(0.08))
      .clipShape(RoundedRectangle(cornerRadius: 7))
  }
}
#endif
