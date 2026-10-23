#if os(macOS)
import AppKit
import SwiftUI
import ZenithKit

struct TransferPublicationView: View {
  let service: LocalService
  @Environment(\.dismiss) private var dismiss
  @State private var snapshot: PublicationSnapshot?
  @State private var loading = false
  @State private var error: String?
  @State private var tailnet = true
  @State private var funnel = false
  @State private var privatePort = "10444"
  @State private var publicPort = 443
  @State private var review: ServicePublicationReview?
  @State private var exported = false

  var body: some View {
    VStack(alignment:.leading,spacing:16) {
      HStack {
        VStack(alignment:.leading,spacing:5) {
          Text("Sharing & network").font(.title.bold())
          Text(service.title).font(.headline)
          Text(service.endpoint).font(.caption.monospaced()).textSelection(.enabled)
        }
        Spacer()
        Button("Done") { dismiss() }
      }
      ScrollView {
        VStack(alignment:.leading,spacing:18) {
          if let snapshot {
            Label(snapshot.running ? "Tailscale connected" : "Tailscale not connected",systemImage:snapshot.running ? "checkmark.shield" : "network.slash")
            Text(snapshot.dnsName).font(.caption.monospaced()).textSelection(.enabled)
            GroupBox("Private Tailnet access") {
              VStack(alignment:.leading,spacing:8) {
                Toggle("Make available to permitted Tailnet devices",isOn:$tailnet)
                Text("Uses Tailscale Serve. Your network’s access rules and the service’s own credential checks both apply.").font(.callout).foregroundStyle(.secondary)
                if tailnet { TextField("Private HTTPS port",text:$privatePort).frame(maxWidth:220) }
              }.frame(maxWidth:.infinity,alignment:.leading).padding(6)
            }
            GroupBox("Public internet access") {
              VStack(alignment:.leading,spacing:8) {
                Toggle("Publish through Tailscale Funnel",isOn:$funnel)
                Text("Anyone can reach this HTTPS address without Tailscale. Publication does not issue credentials or make protected work public.").font(.callout).foregroundStyle(.secondary)
                if funnel {
                  Picker("Public HTTPS port",selection:$publicPort) { ForEach([443,8443,10000],id:\.self) { Text(String($0)).tag($0) } }.frame(maxWidth:280)
                  Text("A public listener is also reachable from the Tailnet. Choose a separate private port when you want both addresses.").font(.caption).foregroundStyle(.secondary)
                }
              }.frame(maxWidth:.infinity,alignment:.leading).padding(6)
            }
            Text("Existing HTTPS ports: " + snapshot.occupiedPorts.sorted().map(String.init).joined(separator:", ")).font(.caption)
            Text("Funnel changes visibility for an entire port. Transfer will not overwrite existing listeners or publish their other paths.").font(.callout).foregroundStyle(.secondary)
            Button("Review publishing setup") { prepare(snapshot) }
              .buttonStyle(TransferPrimaryButtonStyle()).disabled(!tailnet && !funnel)
          } else if loading { ProgressView("Reading Tailscale configuration…") }
          else { Text("Open Tailscale on this Mac, then refresh. This screen does not sign in or change network settings.") }
          if let error { Text(error).foregroundStyle(.red) }
          if let review {
            Divider()
            Text("Proposed addresses").font(.headline)
            if let url=review.tailnetURL { LabeledContent("Private",value:url).textSelection(.enabled) }
            if let url=review.funnelURL { LabeledContent("Public",value:url).textSelection(.enabled) }
            ForEach(review.blockers,id:\.self) { Text($0).font(.callout).foregroundStyle(.secondary) }
            Label("Not published · Review only",systemImage:"doc.text.magnifyingglass").font(.headline)
            Text("Network publication is separate from Wallet ownership and credential grants. Activation will require the service’s owner-authorized configuration adapter and an exact final review.").font(.callout)
            Button("Save setup review…") { export(review) }
            if exported { Text("Review saved. No listener, certificate, grant or Tailscale setting changed.").font(.caption) }
          }
        }.frame(maxWidth:.infinity,alignment:.leading)
      }
      HStack {
        Button("Refresh Tailscale") { Task { await refresh() } }.disabled(loading)
        Spacer()
        Text("No network changes until a supported activation is reviewed").font(.caption).foregroundStyle(.secondary)
      }
    }.padding(24).frame(width:740,height:740)
      .task { await refresh() }
      .onChange(of:tailnet) { _ in clearReview() }
      .onChange(of:funnel) { _ in clearReview() }
      .onChange(of:privatePort) { _ in clearReview() }
      .onChange(of:publicPort) { _ in clearReview() }
  }
  private func clearReview() { review=nil;exported=false;error=nil }
  private func refresh() async {
    guard !loading else { return };loading=true;clearReview();snapshot=nil
    do { snapshot=try await TailscalePublicationInspector.inspect() }
    catch { self.error=PublicationFailure.unavailable.localizedDescription }
    loading=false
  }
  private func prepare(_ snapshot:PublicationSnapshot) {
    do {
      guard let port=tailnet ? Int(privatePort) : 0 else { throw PublicationFailure.invalid }
      review=try ServicePublicationReview.prepare(service:service,snapshot:snapshot,tailnet:tailnet,privatePort:port,funnel:funnel,publicPort:publicPort)
      error=nil;exported=false
    } catch { self.error=PublicationFailure.invalid.localizedDescription }
  }
  private func export(_ review:ServicePublicationReview) {
    let panel=NSSavePanel();panel.nameFieldStringValue="Service-publishing-review.json";panel.allowedContentTypes=[.json]
    guard panel.runModal() == .OK,let url=panel.url else { return }
    do {
      let encoder=JSONEncoder();encoder.outputFormatting=[.prettyPrinted,.sortedKeys,.withoutEscapingSlashes]
      try encoder.encode(review).write(to:url,options:.atomic)
      try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:url.path)
      exported=true
    } catch { self.error="Could not save the review. No network settings changed." }
  }
}
#endif
