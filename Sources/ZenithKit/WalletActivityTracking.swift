import SwiftUI
#if os(macOS)
import AppKit
#else
import UIKit
#endif

public extension View {
  /// Passive, app-local observation of user input. No event payload, typed text,
  /// pointer position or history is read or stored. Never observes other apps.
  func walletUserActivity(_ action: @escaping () -> Void) -> some View {
    background(WalletActivityObserver(action: action).frame(width: 0, height: 0))
  }
}

#if os(macOS)
private struct WalletActivityObserver: NSViewRepresentable {
  let action: () -> Void
  func makeNSView(context: Context) -> ActivityView { let view = ActivityView(); view.action = action; return view }
  func updateNSView(_ view: ActivityView, context: Context) { view.action = action }
  static func dismantleNSView(_ view: ActivityView, coordinator: ()) { view.stop() }
}
private final class ActivityView: NSView {
  var action: () -> Void = {}
  private var monitor: Any?
  override func viewDidMoveToWindow() {
    super.viewDidMoveToWindow(); stop()
    guard window != nil else { return }
    monitor = NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .leftMouseDown, .rightMouseDown, .otherMouseDown, .leftMouseDragged, .scrollWheel]) { [weak self] event in
      if let self, self.window != nil, event.window != nil, NSApp.isActive { self.action() }
      return event
    }
  }
  func stop() { if let monitor { NSEvent.removeMonitor(monitor) }; monitor = nil }
}
#else
private struct WalletActivityObserver: UIViewRepresentable {
  let action: () -> Void
  func makeUIView(context: Context) -> ActivityView { let view = ActivityView(); view.action = action; view.isUserInteractionEnabled = false; return view }
  func updateUIView(_ view: ActivityView, context: Context) { view.action = action }
  static func dismantleUIView(_ view: ActivityView, coordinator: ()) { view.stop() }
}
private final class ActivityView: UIView {
  var action: () -> Void = {}
  private weak var observedWindow: UIWindow?
  private var gesture: ActivityGesture?
  private var tokens: [NSObjectProtocol] = []
  override func didMoveToWindow() {
    super.didMoveToWindow(); stop()
    guard let window else { return }
    let gesture = ActivityGesture(target: nil, action: nil)
    gesture.activity = { [weak self] in self?.action() }
    window.addGestureRecognizer(gesture); observedWindow = window; self.gesture = gesture
    for name in [UITextField.textDidChangeNotification, UITextView.textDidChangeNotification] {
      tokens.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] note in
        guard let self, let view = note.object as? UIView, view.window === self.observedWindow else { return }
        self.action()
      })
    }
  }
  func stop() {
    if let gesture { observedWindow?.removeGestureRecognizer(gesture) }
    gesture = nil; observedWindow = nil
    for token in tokens { NotificationCenter.default.removeObserver(token) }; tokens = []
  }
}
/// Remains passive and fails at the end of each gesture, never claiming a tap
/// or preventing a button, scroll view, text field or another recognizer.
private final class ActivityGesture: UIGestureRecognizer, UIGestureRecognizerDelegate {
  var activity: () -> Void = {}
  override init(target: Any?, action: Selector?) {
    super.init(target: target, action: action)
    cancelsTouchesInView = false; delaysTouchesBegan = false; delaysTouchesEnded = false
    requiresExclusiveTouchType = false; delegate = self
  }
  override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent) { activity() }
  override func touchesMoved(_ touches: Set<UITouch>, with event: UIEvent) { activity() }
  override func touchesEnded(_ touches: Set<UITouch>, with event: UIEvent) { activity(); state = .failed }
  override func touchesCancelled(_ touches: Set<UITouch>, with event: UIEvent) { state = .failed }
  func gestureRecognizer(_ gestureRecognizer: UIGestureRecognizer, shouldRecognizeSimultaneouslyWith otherGestureRecognizer: UIGestureRecognizer) -> Bool { true }
}
#endif
