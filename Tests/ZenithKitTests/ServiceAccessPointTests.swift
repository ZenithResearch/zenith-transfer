import CryptoKit
import XCTest
@testable import ZenithKit

final class ServiceAccessPointTests: XCTestCase {
  func fixture() throws -> ([String:Any], WorkAccessConfiguration) {
    let url = try XCTUnwrap(Bundle.module.url(forResource: "access-point", withExtension: "json"))
    let value = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String:Any])
    let pin = value["pin"] as! [String:String]
    return (value, try WorkAccessConfiguration(name:"Graph", receiver:URL(string:"https://graph.example:9443")!, issuer:pin["issuer"]!, keyID:pin["key_id"]!, publicKey:pin["public_key"]!))
  }
  func testSharedGoldenVectorAndServiceIdentityAreIndependentOfRoute() throws {
    let (raw, configuration) = try fixture()
    let binding = try JSONDecoder().decode(ServiceAccessPoint.self, from:JSONSerialization.data(withJSONObject:raw["binding"]!))
    try binding.verify(configuration:configuration, now:102)
    let resolved = try configuration.withServiceAccessPoint(binding)
    XCTAssertEqual(resolved.serviceID,"service:fixture")
    XCTAssertEqual(resolved.credentialAuthority.receiver,"https://127.0.0.1:58754")
    XCTAssertEqual(resolved.origin,"https://graph.example:9443")
    XCTAssertThrowsError(try binding.verify(configuration:configuration,now:1000))
    let wrong = try WorkAccessConfiguration(name:"Other",receiver:URL(string:"https://evil.example")!,issuer:configuration.issuer,keyID:configuration.authority.key_id,publicKey:configuration.authority.public_key)
    XCTAssertThrowsError(try wrong.withServiceAccessPoint(binding))
    var altered = raw["binding"] as! [String:Any]
    var claims = altered["claims"] as! [String:Any]; claims["service"]="service:other";altered["claims"]=claims
    let bad = try JSONDecoder().decode(ServiceAccessPoint.self, from:JSONSerialization.data(withJSONObject:altered))
    XCTAssertThrowsError(try configuration.withServiceAccessPoint(bad))
  }
  func testLegacyProfilesKeepTheirOriginalAuthorityAndJournal() throws {
    let (_, value) = try fixture()
    XCTAssertNil(value.serviceID)
    XCTAssertEqual(value.authorityJournalKey,value.origin)
    XCTAssertEqual(value.credentialAuthority,value.authority)
  }
  func bound(_ origin: String) throws -> WorkAccessConfiguration {
    let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating:1,count:32))
    let publicKey = key.publicKey.rawRepresentation.map { String(format:"%02x",$0) }.joined()
    let configuration = try WorkAccessConfiguration(name:"Graph", receiver:URL(string:origin)!, issuer:"provider:fixture", keyID:"key:v1", publicKey:publicKey)
    let now = UInt64(Date().timeIntervalSince1970)
    let claims = ServiceAccessPoint.Claims(schema:"secs.service-access-point.v1",issuer:configuration.issuer,key_id:"key:v1",service:"service:fixture",origin:origin,authority_receiver:"https://authority.example",prefix:"/service/v1",not_before:now-1,not_after:now+1000)
    let encoder=JSONEncoder();encoder.outputFormatting=[.sortedKeys,.withoutEscapingSlashes]
    let signature=try key.signature(for:Data("secs.service-access-point.v1\0".utf8)+encoder.encode(claims)).map { String(format:"%02x",$0) }.joined()
    return try configuration.withServiceAccessPoint(ServiceAccessPoint(claims:claims,signature:signature))
  }
  func testAliasesUseOneRequestJournalAndKeepTransportChoice() throws {
    let a=try bound("https://lan.example:18443"), b=try bound("https://tailnet.example:9443")
    XCTAssertEqual(a.serviceID,b.serviceID)
    XCTAssertEqual(a.authorityJournalKey,b.authorityJournalKey)
    XCTAssertEqual(a.credentialAuthority,b.credentialAuthority)
    XCTAssertEqual(try a.apiURL("/devgraph/access-requests/v2/actions").absoluteString,"https://lan.example:18443/service/v1/devgraph/access-requests/v2/actions")
    XCTAssertEqual(try b.apiURL("/devgraph/access-requests/v2/actions").host,"tailnet.example")
    let directory=FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:directory) }
    let store=try WorkAccessRequestStore(directory:directory)
    let original=try store.begin(receiver:a.authorityJournalKey,subject:String(repeating:"11",count:32),installation:String(repeating:"22",count:16))
    XCTAssertEqual(try store.begin(receiver:b.authorityJournalKey,subject:original.subject,installation:original.installation),original)
    XCTAssertNil(try store.existing(receiver:a.origin,subject:original.subject,installation:original.installation))
  }
  func testBindingDecoderRejectsDuplicatesAndExtraFields() throws {
    let configuration=try bound("https://graph.example")
    let binding=try JSONEncoder().encode(configuration.service_access_point!)
    let data=Data("{\"schema\":\"devgraph.service-access-point.v1\",\"schema\":\"devgraph.service-access-point.v1\",\"binding\":".utf8)+binding+Data("}".utf8)
    XCTAssertThrowsError(try ServiceAccessPoint.decode(data,configuration:configuration))
  }

}
