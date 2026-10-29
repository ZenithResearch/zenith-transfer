#if os(macOS)
import AppKit
import SwiftUI
import ZenithKit

struct TransferSessionReviewView: View {
  @ObservedObject var controller: TransferSessionReviewController
  @ObservedObject var walletModel: TransferModel
  @State private var editedExpiry = Date()
  @State private var unlocking = false
  @State private var now = Date()
  private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()
  var body: some View {
    VStack(spacing: 0) {
      HStack(alignment: .top) {
        VStack(alignment: .leading, spacing: 5) {
          Label("Zenith Wallet", systemImage: "wallet.pass").font(.headline)
          Text("Review session access").font(.title.bold())
          Text("Owner approval").font(.caption).foregroundStyle(.secondary)
        }
        Spacer(); Button("Close") { controller.dismiss() }.keyboardShortcut(.cancelAction)
      }.padding(24)
      Divider()
      if let handle = controller.active, let record = controller.records[handle], let review = try? controller.review(handle) {
        let dirtyExpiry = abs(editedExpiry.timeIntervalSince1970 - Double(review.expiresAt)) >= 1
        ScrollView {
          VStack(alignment: .leading, spacing: 20) {
            GroupBox {
              VStack(alignment: .leading, spacing: 8) {
                Text(review.sessionLabel).font(.title3.bold())
                Text(review.purpose)
                Text("Label supplied by the requesting local application. Approval applies to the public key below.")
                  .font(.caption).foregroundStyle(.secondary)
                LabeledContent("Session key") { Text(review.holderPublicKey).font(.caption.monospaced()).textSelection(.enabled) }
                LabeledContent("Service") { Text(review.service).font(.callout.monospaced()).textSelection(.enabled) }
              }.frame(maxWidth: .infinity, alignment: .leading).padding(6)
            }
            VStack(alignment: .leading, spacing: 12) {
              HStack { Text("Requested access").font(.headline); Spacer(); Label("Fixed to this request", systemImage: "lock").font(.caption).foregroundStyle(.secondary) }
              ForEach(Array(review.permissions.enumerated()), id: \.offset) { _, permission in
                VStack(alignment: .leading, spacing: 7) {
                  Text(permission.title).font(.headline)
                  Text(permission.operation).font(.caption.monospaced()).textSelection(.enabled)
                  DisclosureGroup("Resources and conditions") {
                    VStack(alignment: .leading, spacing: 8) {
                      Text(permission.resource)
                      if let roles = permission.roles { Text(roles) }
                      Text(permission.conditions)
                    }.font(.caption.monospaced()).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(.top, 6)
                  }
                }.padding(14).background(Color.primary.opacity(0.035)).clipShape(RoundedRectangle(cornerRadius: 10))
              }
            }
            if controller.endedClients.contains(record.clientID) {
              Label("This local session has ended", systemImage: "stop.circle").font(.headline)
              Text("Transfer no longer accepts calls or approvals from this adapter. Helper cleanup does not confirm server-side grant revocation; expiry still applies.").foregroundStyle(.secondary)
            } else if !record.dispatched && record.state == .awaitingHuman {
              GroupBox("Access expiry") {
                VStack(alignment: .leading, spacing: 10) {
                  DatePicker("Expires", selection: $editedExpiry, displayedComponents: [.date, .hourAndMinute])
                    .disabled(controller.busy)
                  HStack {
                    Text("Currently reviewed: \(Date(timeIntervalSince1970: TimeInterval(review.expiresAt)).formatted())")
                      .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Update review") {
                      let seconds = editedExpiry.timeIntervalSince1970
                      guard seconds.isFinite, seconds >= 0, seconds <= 9_007_199_254_740_991 else { return }
                      Task { await controller.changeExpiry(UInt64(seconds)) }
                    }.disabled(controller.busy)
                  }
                  Text("Changing expiry creates a fresh review within the service’s limits. It does not extend an issued credential or change your Wallet’s lock timer.")
                    .font(.caption).foregroundStyle(.secondary)
                  if dirtyExpiry { Label("Update the review to apply this expiry before approval.", systemImage: "arrow.triangle.2.circlepath").font(.callout).foregroundStyle(.orange) }
                }.padding(6)
              }
              if let consent = controller.consent {
                Label("Wallet verified the exact session and signing request", systemImage: "checkmark.shield")
                  .foregroundStyle(Color.accentColor)
                DisclosureGroup("Verified signing details") {
                  Text(pretty(consent.details)).font(.caption.monospaced()).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
              } else {
                Label("No access has been granted", systemImage: "key").foregroundStyle(.secondary)
              }
              if now.timeIntervalSince1970 >= Double(review.reviewDeadline) {
                Label("This review expired. Update the review before approving.", systemImage: "clock.badge.exclamationmark")
                  .font(.callout).foregroundStyle(.orange)
              }
            } else {
              Label(stateTitle(record, review), systemImage: record.state == .issued ? "checkmark.shield" : "clock")
                .font(.headline)
              Text(record.dispatched ? "Keep this original request. Checking its result never submits another approval." : "No issuance was submitted for this locally declined request.")
                .foregroundStyle(.secondary)
            }
            if let error = controller.error { Text(error).foregroundStyle(.red).accessibilityIdentifier("session-review-error") }
          }.padding(24)
        }.task(id: review.digest) { editedExpiry = Date(timeIntervalSince1970: TimeInterval(review.expiresAt)) }
        Divider()
        HStack(spacing: 12) {
          if controller.endedClients.contains(record.clientID) {
            Spacer(); Button("Close") { controller.dismiss() }
          } else if !record.dispatched && record.state == .awaitingHuman {
            Button("Decline request", role: .destructive) { controller.declineNativeReview() }.disabled(controller.busy)
            Spacer()
            if !walletModel.walletUnlocked {
              Button("Unlock Wallet") { unlocking = true }.buttonStyle(TransferPrimaryButtonStyle())
            } else if controller.consent == nil {
              Button("Review in Wallet") { Task { await controller.prepareNativeReview() } }
                .buttonStyle(TransferPrimaryButtonStyle()).disabled(controller.busy || dirtyExpiry || now.timeIntervalSince1970 >= Double(review.reviewDeadline))
            } else {
              Button("Approve session access") { Task { await controller.approveNativeReview(reviewedDigest: review.digest, reviewedExpiry: review.expiresAt) } }
                .buttonStyle(TransferPrimaryButtonStyle()).disabled(controller.busy || dirtyExpiry || now.timeIntervalSince1970 >= Double(review.reviewDeadline))
            }
          } else {
            Spacer()
            if record.dispatched {
              Button("Check original result") { Task { await controller.checkActiveResult() } }
                .buttonStyle(TransferPrimaryButtonStyle()).disabled(controller.busy)
            }
          }
          if controller.busy { ProgressView().controlSize(.small) }
        }.padding(20)
        .onChange(of: editedExpiry) { _ in if dirtyExpiry { controller.invalidatePreparedConsent() } }
      } else {
        Text("Choose a pending session request in Settings → Session requests.").foregroundStyle(.secondary).padding(32)
        Spacer()
      }
    }.frame(minWidth: 640, minHeight: 580)
      .sheet(isPresented: $unlocking) { TransferWalletSheet(model: walletModel) }
      .onReceive(timer) { now = $0; walletModel.expire() }
      .onChange(of: walletModel.walletUnlocked) { unlocked in if !unlocked { controller.invalidatePreparedConsent() } }
      .walletUserActivity { walletModel.userActivity() }
  }
  private func pretty(_ data: Data) -> String {
    guard let value = try? JSONSerialization.jsonObject(with: data),
      let formatted = try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]) else { return "Details unavailable" }
    return String(decoding: formatted, as: UTF8.self)
  }
  private func stateTitle(_ record: SessionReviewRecord, _ review: SessionAccessReview) -> String {
    if record.state == .issued { return now.timeIntervalSince1970 >= Double(review.expiresAt) ? "Session access expired" : "Session access issued" }
    return [.denied: "Request declined", .cancelled: "Request cancelled", .expired: "Request expired", .revoked: "Session access revoked"][record.state]
      ?? "Original result needs confirmation"
  }
}

struct TransferSessionSettingsView: View {
  @ObservedObject var controller: TransferSessionReviewController
  @State private var copied = false
  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 22) {
        Text("Session requests").font(.largeTitle.bold())
        Text("Let a local MCP client ask your Wallet for short-lived access. You review the service, resources, operations and expiry in a native window.").foregroundStyle(.secondary)
        Picker("Approval source for new requests", selection: $controller.approvalSource) {
          ForEach(TransferSessionReviewController.ApprovalSource.allCases, id: \.self) { source in Text(source.rawValue).tag(source) }
        }
        Text("Owner approval uses your administrator role. Saved reusable grant uses a grant already saved in this Wallet. A denial never changes the approval source; existing requests retain their original source.").font(.caption).foregroundStyle(.secondary)
        if controller.approvalSource == .savedGrant && !controller.savedGrantSourceAvailable {
          Label("Saved-grant session provider needs setup", systemImage: "info.circle").foregroundStyle(.secondary)
        }
        Toggle("Allow local session review requests", isOn: Binding(get: { controller.enabled }, set: { controller.setEnabled($0) }))
        Text("Uses a private local socket. It opens no public network listener and does not let a client approve or sign. Wallet and grant backups are unchanged.")
          .font(.callout).foregroundStyle(.secondary)
        Button(copied ? "Codex MCP configuration copied" : "Copy Codex MCP configuration") { copyConfiguration() }
        Text("A qualified local credential provider must also be installed. Unsupported services remain unavailable; enabling this channel grants no access.")
          .font(.caption).foregroundStyle(.secondary)
        if controller.availableServices.isEmpty {
          Label("No qualified local session provider installed", systemImage: "info.circle").foregroundStyle(.secondary)
        } else {
          ForEach(controller.availableServices, id: \.service) { service in
            VStack(alignment: .leading, spacing: 4) {
              Text(service.name).font(.headline)
              Text(service.read_available ? "Session read access available" : "Session read access unavailable").font(.caption)
              Text(service.write_available ? "Session write access available" : "Session write access unavailable").font(.caption).foregroundStyle(.secondary)
            }
          }
        }
        Divider()
        Text("Requests and session access").font(.headline)
        if controller.records.isEmpty { Text("No session requests yet.").foregroundStyle(.secondary) }
        ForEach(controller.records.keys.sorted(), id: \.self) { handle in
          if let record = controller.records[handle], let review = try? controller.review(handle) {
            HStack {
              VStack(alignment: .leading, spacing: 5) {
                Text(review.sessionLabel).font(.headline)
                Text(review.service).font(.caption.monospaced()).textSelection(.enabled)
                Text(controller.endedClients.contains(record.clientID) ? "Local session ended" : record.dispatched && record.result == nil ? "Check original result" : record.state.rawValue.replacingOccurrences(of: "_", with: " "))
                  .font(.caption).foregroundStyle(.secondary)
              }
              Spacer(); Button("Review") { controller.show(handle) }
            }.padding(.vertical, 8)
          }
        }
        if let error = controller.error { Text(error).foregroundStyle(.red) }
      }.frame(maxWidth: 760, alignment: .leading).padding(24).frame(maxWidth: .infinity)
    }
      .task { await controller.refreshServices() }
      .onChange(of: controller.approvalSource) { _ in Task { await controller.refreshServices() } }
  }
  private func copyConfiguration() {
    let resource: URL
    if let root = Bundle.main.resourceURL,
      let bundle = Bundle(url: root.appendingPathComponent("ZenithKit_ZenithTransfer.bundle")), let directory = bundle.resourceURL { resource = directory }
    else { resource = Bundle.module.resourceURL! }
    guard let text = try? TransferMCPConfiguration.codex(resourceDirectory: resource) else { return }
    NSPasteboard.general.clearContents(); NSPasteboard.general.setString(text, forType: .string); copied = true
  }
}

enum TransferMCPConfiguration {
  static func script(resourceDirectory: URL) throws -> URL {
    let file = resourceDirectory.appendingPathComponent("Resources/MCP/transfer_mcp.py")
    guard FileManager.default.isReadableFile(atPath: file.path) else { throw SessionReviewBridgeError.unavailable }
    return file
  }
  static func codex(resourceDirectory: URL) throws -> String {
    let file = try script(resourceDirectory: resourceDirectory)
    let args = try JSONSerialization.data(withJSONObject: ["-I", file.path], options: [.withoutEscapingSlashes])
    // JSON string arrays are also valid TOML here; no shell interpolation.
    return "[mcp_servers.zenith_transfer_wallet]\ncommand = \"/usr/bin/python3\"\nargs = "
      + String(decoding: args, as: UTF8.self) + "\n"
  }
}
#endif
