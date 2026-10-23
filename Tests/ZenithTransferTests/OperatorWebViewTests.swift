#if os(macOS)
import Foundation
import CryptoKit
import WebKit
import XCTest
import ZenithKit
@testable import ZenithTransfer

private final class OperatorResponse: URLProtocol {
  static var handler: (([String:Any],String) -> [String:Any])?
  override class func canInit(with request: URLRequest) -> Bool { true }
  override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
  override func startLoading() {
    do {
      var body=request.httpBody
      if body == nil, let stream=request.httpBodyStream {
        stream.open();defer {stream.close()};var data=Data();var buffer=[UInt8](repeating:0,count:4096)
        while stream.hasBytesAvailable {let n=stream.read(&buffer,maxLength:buffer.count);if n<=0 {break};data.append(contentsOf:buffer.prefix(n))};body=data
      }
      let input=try JSONSerialization.jsonObject(with:body ?? Data()) as! [String:Any]
      let result=Self.handler!(input,request.url!.path)
      let bytes=try JSONSerialization.data(withJSONObject:result)
      let response=HTTPURLResponse(url:request.url!,statusCode:200,httpVersion:"HTTP/1.1",headerFields:["Content-Length":String(bytes.count)])!
      client?.urlProtocol(self,didReceive:response,cacheStoragePolicy:.notAllowed)
      client?.urlProtocol(self,didLoad:bytes);client?.urlProtocolDidFinishLoading(self)
    } catch {client?.urlProtocol(self,didFailWithError:error)}
  }
  override func stopLoading() {}
}

final class OperatorWebViewTests: XCTestCase {
  @MainActor func testBundledEditorUsesNativeProofAndClearsOnlyAcceptedOriginalResult() async throws {
    let root=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer {try? FileManager.default.removeItem(at:root);OperatorResponse.handler=nil}
    let repo=try WalletRepository(directory:root.appendingPathComponent("wallet"))
    _=try await repo.create(password:"disposable web test password")
    let backup=try await repo.exportRecovery(password:"disposable backup password")
    _=try await repo.verifyBackup(file:backup,password:"disposable backup password")
    _=await repo.lock()
    let config=try WorkAccessConfiguration(name:"Fixture",receiver:URL(string:"https://fixture.example")!,issuer:"fixture",keyID:"key",publicKey:String(repeating:"12",count:32))
    var actions=0, grantDecisions=0, tamperOperation=false
    var originalResult: [String:Any]?
    OperatorResponse.handler={input,path in
      if path.hasSuffix("/challenges") {
        let now=Int(Date().timeIntervalSince1970)
        return ["schema":"castalia.access-request-challenge.v1","challenge_id":String(repeating:"aa",count:16),"nonce":String(repeating:"A",count:43),"issuer":"fixture","receiver":"https://fixture.example","subject_public_key":input["subject_public_key"]!,"installation_id":input["installation_id"]!,"operation":(tamperOperation ? "access.status" : ((["inbox":"access.inbox","approve":"access.decide","status":"access.status"][(input["action"] as? [String:Any])?["action"] as? String ?? ""]) ?? "access.review")),"issued_at":now,"expires_at":now+120,"details":["action":input["action"]!,"policy_revision":1,"policy_digest_sha256":String(repeating:"bb",count:32)]]
      }
      actions += 1
      XCTAssertNotNil(input["signature"] as? String)
      let challenge=input["challenge"] as! [String:Any],details=challenge["details"] as! [String:Any],action=details["action"] as! [String:Any]
      if action["action"] as? String == "approve" {
        grantDecisions += 1
        let selection=action["selection"] as! [String:Any]
        let canonical=try! JSONSerialization.data(withJSONObject:selection["read"]!,options:[.sortedKeys,.withoutEscapingSlashes])
        let digest=SHA256.hash(data:canonical).map {String(format:"%02x",$0)}.joined()
        originalResult=["schema":"devgraph.access-operator-result.v2","action_id":action["action_id"]!,"authority_issued":false,"request_id":action["request_id"]!,"request_digest_sha256":action["request_digest_sha256"]!,"version":2,"status":"active","activation":["active":true,"credential_issued":false,"assignment_digest":digest]]
        return ["schema":"devgraph.access-operator-result.v2","authority_issued":false] // intentionally incomplete response
      }
      if action["action"] as? String == "status" {
        return ["schema":"devgraph.access-operator-result.v1","action_id":action["action_id"]!,"original_action_id":action["original_action_id"]!,"status":"reconciled","authority_issued":false,"result":originalResult!]
      }
      return ["schema":"devgraph.access-operator-result.v1","action_id":action["action_id"]!,"authority_issued":false,"inbox":["items":[],"total":0,"next_cursor":NSNull()],"ceiling":["schema":"devgraph.access-draft.v5","issuer":"fixture","receiver":"https://fixture.example","read_grants":[],"write_grants":[],"lifetime_seconds":300,"validity":["schema":"castalia.grant-validity.v1","mode":"until_revoked","not_before":1]],"ceiling_digest_sha256":String(repeating:"cc",count:32)]
    }
    let session=URLSessionConfiguration.ephemeral;session.protocolClasses=[OperatorResponse.self]
    let journalRoot=root.appendingPathComponent("actions")
    var bridge=TransferOperatorBridge(resource:try RegisteredResource(configuration:config),repository:repo,transport:PrivateTransport(configuration:session),journalDirectory:journalRoot)
    var view=bridge.makeWebView()
    defer {bridge.cancel();view.configuration.userContentController.removeScriptMessageHandler(forName:"operator",contentWorld:.page)}
    func waitFor(_ expression:String) async throws {
      for _ in 0..<100 {
        if (try? await view.evaluateJavaScript(expression)) as? Bool == true {return}
        try await Task.sleep(nanoseconds:100_000_000)
      }
      let text=(try? await view.evaluateJavaScript("document.body.innerText")) as? String ?? "Page unavailable"
      XCTFail("Timed out: \(expression): \(text); \(view.url?.absoluteString ?? "no URL"); \(bridge.failure ?? "no navigation error")")
      throw NSError(domain:"OperatorWebViewTests",code:1)
    }
    try await waitFor("!!document.getElementById('refresh')?.onclick && document.getElementById('refresh').disabled && document.getElementById('wallet-read-connection').textContent.includes('Use Wallet')")
    XCTAssertEqual(actions,0,"A locked manager cannot submit an operator action")
    _=try await repo.unlock(password:"disposable web test password")
    bridge.walletStateDidChange(true)
    try await waitFor("!document.getElementById('refresh').disabled")
    _=try await view.evaluateJavaScript("document.getElementById('refresh').click()")
    try await waitFor("!document.getElementById('confirm').hidden")
    _=try await view.evaluateJavaScript("document.getElementById('confirm').click()")
    for _ in 0..<100 {if bridge.consent != nil {break};try await Task.sleep(nanoseconds:100_000_000)}
    XCTAssertEqual(bridge.consent?.operation,"access.inbox")
    XCTAssertTrue(bridge.disclosure.contains("policy_digest_sha256"))
    XCTAssertEqual(actions,0,"No action sent before human consent")
    bridge.resolve(true)
    try await waitFor("document.getElementById('status').textContent.startsWith('Inbox loaded')")
    for _ in 0..<20 {
      if try OperatorJournal(directory:journalRoot,origin:config.origin).load() == nil {break}
      try await Task.sleep(nanoseconds:100_000_000)
    }
    XCTAssertEqual(actions,1)
    XCTAssertNil(try OperatorJournal(directory:journalRoot,origin:config.origin).load())
    XCTAssertEqual(view.url?.scheme,"zenith-operator")
    let prepareGrant = """
      const {AccessOperatorClient}=await import('/access/client.mjs');
      const {makeSelection}=await import('/access/core.mjs');
      const identity=JSON.parse(await ZenithOperator.call('identity'));
      const wallet=DevgraphWalletAccess.mount(document.getElementById('wallet-read-connection'),{onChange:()=>{}}); wallet.requestIdentity=identity;
      const c=new AccessOperatorClient({wallet,fetchImpl:ZenithOperator.fetch,storage:ZenithOperator.storage,origin:ZenithOperator.origin});
      const now=Math.floor(Date.now()/1000);
      const ceiling={schema:'devgraph.access-draft.v5',issuer:'fixture',receiver:ZenithOperator.origin,lifetime_seconds:300,validity:{schema:'castalia.grant-validity.v1',mode:'until_revoked',not_before:1},read_grants:[{scope:'devgraph.work.read',operations:['list','get'],relationship_types:[],work_kinds:['Task'],work_ids:['Task/example'],include_archived:false}],write_grants:[]};
      const selection=makeSelection({ceiling,ceilingDigest:'d'.repeat(64),recipient:identity,mode:'read',validity:{schema:'castalia.grant-validity.v1',mode:'until_revoked',not_before:now},now});
      await c.prepare({schema:'devgraph.access-operator-action.v6',action:'approve',request_id:'a'.repeat(32),request_digest_sha256:'b'.repeat(64),expected_version:1,previous_assignment_digest:null,review_id:'c'.repeat(32),selection});
      globalThis.fixtureClient=c;
      c.approve().catch(error=>{globalThis.fixtureOutcome=error.message;});
      return true;
      """
    _=try await view.callAsyncJavaScript(prepareGrant,arguments:[:],in:nil,contentWorld:.page)
    for _ in 0..<100 {if bridge.consent != nil {break};try await Task.sleep(nanoseconds:100_000_000)}
    XCTAssertEqual(bridge.consent?.operation,"access.decide")
    XCTAssertTrue(bridge.disclosure.contains("until_revoked"))
    XCTAssertEqual(grantDecisions,0)
    bridge.resolve(true)
    try await waitFor("globalThis.fixtureOutcome==='operator_outcome_unknown'")
    XCTAssertEqual(grantDecisions,1)
    let retained=try XCTUnwrap(OperatorJournal(directory:journalRoot,origin:config.origin).load())
    XCTAssertFalse(String(decoding:retained,as:UTF8.self).contains("signature"))
    _=await repo.lock()
    bridge.walletStateDidChange(false)
    try await waitFor("document.getElementById('recover').disabled")
    XCTAssertEqual(try OperatorJournal(directory:journalRoot,origin:config.origin).load(),retained)
    _=try await repo.unlock(password:"disposable web test password")
    bridge.walletStateDidChange(true)
    try await waitFor("!document.getElementById('recover').disabled")
    XCTAssertEqual(try OperatorJournal(directory:journalRoot,origin:config.origin).load(),retained,
      "Unlock refresh must preserve the original uncertain action without dispatch")
    XCTAssertEqual(grantDecisions,1)
    bridge.cancel();view.stopLoading();view.configuration.userContentController.removeScriptMessageHandler(forName:"operator",contentWorld:.page)
    bridge=TransferOperatorBridge(resource:try RegisteredResource(configuration:config),repository:repo,transport:PrivateTransport(configuration:session),journalDirectory:journalRoot)
    view=bridge.makeWebView()
    try await waitFor("!!document.getElementById('recover') && !document.getElementById('recover').hidden && !document.getElementById('recover').disabled")
    _=try await view.evaluateJavaScript("document.getElementById('recover').click()")
    try await waitFor("!document.getElementById('confirm').hidden")
    _=try await view.evaluateJavaScript("document.getElementById('confirm').click()")
    for _ in 0..<100 {if bridge.consent != nil {break};try await Task.sleep(nanoseconds:100_000_000)}
    XCTAssertEqual(bridge.consent?.operation,"access.status")
    bridge.resolve(true)
    try await waitFor("document.getElementById('status').textContent.startsWith('Original approval committed')")
    XCTAssertEqual(grantDecisions,1,"Recovery must not repeat the grant decision")
    for _ in 0..<20 {
      if try OperatorJournal(directory:journalRoot,origin:config.origin).load() == nil {break}
      try await Task.sleep(nanoseconds:100_000_000)
    }
    XCTAssertNil(try OperatorJournal(directory:journalRoot,origin:config.origin).load())
    let rejected=try await view.callAsyncJavaScript("try{await ZenithOperator.call('post',{path:'/work-operations/v1',body:'{}'});return false;}catch{return true;}",arguments:[:],in:nil,contentWorld:.page) as? Bool
    XCTAssertEqual(rejected,true,"The grant bridge cannot call a Work mutation endpoint")
    XCTAssertEqual(actions,3)
    tamperOperation=true
    let mismatch=try await view.callAsyncJavaScript("const identity=JSON.parse(await ZenithOperator.call('identity'));try{await ZenithOperator.call('post',{path:'/devgraph/access-operator/v1/challenges',body:JSON.stringify({...identity,action:{schema:'devgraph.access-operator-action.v1',action:'inbox',action_id:'f'.repeat(32)}})});return false;}catch{return true;}",arguments:[:],in:nil,contentWorld:.page) as? Bool
    XCTAssertEqual(mismatch,true,"A server cannot label an inbox action as a status-only proof")
    XCTAssertNil(bridge.consent)
    let unknown=try await view.callAsyncJavaScript("try{await ZenithOperator.call('exportSeed');return false;}catch{return true;}",arguments:[:],in:nil,contentWorld:.page) as? Bool
    XCTAssertEqual(unknown,true,"There is no general custody/signing bridge")
    XCTAssertEqual(actions,3)

  }
}
#endif
