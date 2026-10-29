import SwiftUI

/// Human review only. Neither MCP nor the receiver can invoke this button.
public struct HolderSessionReviewView: View {
  @ObservedObject private var model: HolderSessionReviewModel
  private let unlocked: Bool
  private let unlock: () -> Void
  @State private var lifetime: Double = 300
  @State private var selected: Set<Int> = []
  @State private var now = Date()
  private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()
  public init(model: HolderSessionReviewModel, unlocked: Bool, unlock: @escaping () -> Void) {
    self.model = model; self.unlocked = unlocked; self.unlock = unlock
  }
  public var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 20) {
        Label("Zenith Wallet · Session access", systemImage: "wallet.pass").font(.title2.bold())
        Text("Saved reusable grant").font(.caption).foregroundStyle(.secondary)
        Text(model.label).font(.headline)
        Text(model.purpose)
        Text(model.service).font(.caption.monospaced()).textSelection(.enabled)
        Text("The requesting app supplied the label and purpose. Only the permissions and fixed expiry you approve grant access.").font(.caption).foregroundStyle(.secondary)
        if model.mayEdit {
          VStack(alignment: .leading, spacing: 10) {
            Text("Access duration").font(.headline)
            Slider(value: $lifetime, in: 1...Double(max(2, model.maximumLifetime)), step: 1)
            Text("\(Int(lifetime)) seconds · maximum \(model.maximumLifetime) seconds")
            if let c = model.challenge { Text("Reviewed expiry: \(Date(timeIntervalSince1970: Double(c.expiresAt)).formatted())").font(.caption) }
          }
          ForEach(Array(model.permissions.enumerated()), id: \.offset) { index, p in
            Toggle(isOn: Binding(get: { selected.contains(index) }, set: { if $0 { selected.insert(index) } else { selected.remove(index) } })) {
              VStack(alignment: .leading, spacing: 5) {
                Text(p.title).font(.headline)
                Text(p.operation).font(.caption.monospaced())
                DisclosureGroup("Resources and conditions") {
                  Text(p.resource); if let roles = p.roles { Text(roles) }; Text(p.conditions)
                }.font(.caption.monospaced())
              }
            }
          }
          Button(model.challenge == nil ? "Prepare session review" : "Update scope and expiry") {
            Task { await model.prepare(lifetime: UInt64(lifetime), permissions: selection()) }
          }.disabled(model.busy || !unlocked || (model.challenge != nil && selected.isEmpty))
          Text("Changing scope or expiry creates a new request and temporary key. It never renews an issued session.").font(.caption).foregroundStyle(.secondary)
        }
        if let c = model.challenge {
          Text("Session public key: \(c.intent.session.publicKey)").font(.caption.monospaced()).textSelection(.enabled)
          if model.phase == .awaitingHuman {
            Text("No access has been granted. Onward delegation is disabled.")
            if now.timeIntervalSince1970 >= Double(c.reviewDeadline) { Text("Review expired. Update it before approving.").foregroundStyle(.orange) }
            if unlocked {
              Button("Allow session access") { Task { await model.approve(digest: c.digest, expiresAt: c.expiresAt) } }
                .buttonStyle(.borderedProminent).disabled(model.busy || dirty || now.timeIntervalSince1970 >= Double(c.reviewDeadline))
            }
          } else {
            Text(model.phase.rawValue).font(.headline)
            Text("Expiry: \(Date(timeIntervalSince1970: Double(c.expiresAt)).formatted())")
            if [.issued, .outcomeUnknown, .dispatched].contains(model.phase) {
              Button("Check original result") { Task { await model.checkOriginalResult() } }.disabled(model.busy)
            }
          }
        }
        if !unlocked && model.phase != .issued { Button("Unlock Wallet", action: unlock).buttonStyle(.borderedProminent) }
        if let error = model.error { Text(error).foregroundStyle(.red) }
        if model.busy { ProgressView() }
        Button(model.phase == .issued ? "End this session" : "Decline and close", role: .destructive) { Task { await model.close() } }.disabled(model.busy)
      }.padding(24).frame(maxWidth: 760, alignment: .leading)
    }.task { lifetime = Double(model.proposedLifetime) }
      .onChange(of: model.challenge?.digest) { _ in selected = Set(model.permissions.indices); if let c = model.challenge { lifetime = Double(c.expiresAt - c.issuedAt) } }
      .onChange(of: unlocked) { value in if !value { Task { await model.invalidateConsent() } } }
      .onReceive(timer) { now = $0 }
  }
  private var dirty: Bool {
    guard let c = model.challenge else { return true }
    return selected != Set(model.permissions.indices) || UInt64(lifetime) != c.expiresAt - c.issuedAt
  }
  private func selection() -> Data? {
    guard let c = model.challenge, let values = try? HS.value(c.permissionData) as? [Any] else { return nil }
    return try? HS.encode(values.enumerated().filter { selected.contains($0.offset) }.map(\.element))
  }
}
