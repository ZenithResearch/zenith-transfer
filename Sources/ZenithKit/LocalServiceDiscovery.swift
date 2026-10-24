#if os(macOS)
import CryptoKit
import Darwin
import Foundation

/// A launched interface belongs to a graph, but has its own selectable identity.
/// Registry metadata is advisory; fresh endpoint checks never grant trust/access.
public struct LocalService: Decodable, Identifiable, Equatable, Sendable {
  public enum Interface: String, Decodable, Sendable { case privateAPI = "private-api", walletAPI = "wallet-api" }
  public let instance_id: String
  public let resource_id: String
  public let interface: Interface
  public let name: String
  public let endpoint: String
  public let connection: WorkAccessConfiguration?
  public let updated_at: UInt64
  public var id: String { instance_id }
  public var title: String { name + (interface == .walletAPI ? " · Wallet API" : " · Private API") }
  public static func instanceID(resourceID: String, interface: Interface, endpoint: String) throws -> String {
    guard let namespace=UUID(uuidString:resourceID) else { throw WorkServerSetupError.profile }
    var uuid=namespace.uuid
    let prefix=withUnsafeBytes(of:&uuid) { Data($0) }
    var bytes=Array(Insecure.SHA1.hash(data:prefix+Data((interface.rawValue+"\n"+endpoint).utf8)).prefix(16))
    bytes[6]=(bytes[6]&0x0f)|0x50;bytes[8]=(bytes[8]&0x3f)|0x80
    return NSUUID(uuidBytes:bytes).uuidString.lowercased()
  }
  public static func decode(_ data: Data) throws -> Self {
    var strict=OwnerPlanJSON(data,maximumBytes:LocalResource.maximumBytes);try strict.validate()
    guard let raw=try JSONSerialization.jsonObject(with:data) as? [String:Any],
      Set(raw.keys)==["schema","instance_id","resource_id","kind","interface","name","endpoint","connection","updated_at"],
      raw["schema"] as? String == "zenith.local-service.v1" else { throw WorkServerSetupError.profile }
    var resource=raw;resource.removeValue(forKey:"instance_id");resource.removeValue(forKey:"interface");resource["schema"]=LocalResource.schema
    _ = try LocalResource.decode(JSONSerialization.data(withJSONObject:resource))
    let value=try JSONDecoder().decode(Self.self,from:data)
    guard value.id == (try instanceID(resourceID:value.resource_id,interface:value.interface,endpoint:value.endpoint)) else { throw WorkServerSetupError.profile }
    switch value.interface {
    case .privateAPI:
      guard value.connection == nil,let origin=URL(string:value.endpoint),origin.scheme == "http",origin.host == "127.0.0.1",
        let port=origin.port,value.endpoint == "http://127.0.0.1:\(port)" else { throw WorkServerSetupError.profile }
    case .walletAPI: guard value.connection != nil else { throw WorkServerSetupError.profile }
    }
    return value
  }
}

public struct LocalServiceScan: Sendable {
  public let services: [LocalService]
  public let rejected: Int
  public let unavailable: Bool
}

public enum LocalServiceDiscovery {
  public static func directory(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> URL {
    home.appendingPathComponent(".zenith/services/v1",isDirectory:true)
  }
  public static func scan(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> LocalServiceScan {
    var descriptor=Darwin.open(home.path,O_RDONLY|O_DIRECTORY)
    guard descriptor>=0 else { return .init(services:[],rejected:0,unavailable:true) }
    defer { Darwin.close(descriptor) }
    for part in [".zenith","services","v1"] {
      let next=openat(descriptor,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK)
      guard next>=0 else { return .init(services:[],rejected:0,unavailable:errno != ENOENT) }
      var info=stat()
      guard fstat(next,&info)==0,info.st_uid==getuid(),info.st_mode&0o077==0 else {
        Darwin.close(next);return .init(services:[],rejected:0,unavailable:true)
      }
      Darwin.close(descriptor);descriptor=next
    }
    guard let stream=fdopendir(dup(descriptor)) else { return .init(services:[],rejected:0,unavailable:true) }
    defer { closedir(stream) }
    var names:[String]=[]
    while let item=readdir(stream) {
      let name=withUnsafePointer(to:&item.pointee.d_name) { $0.withMemoryRebound(to:CChar.self,capacity:Int(MAXNAMLEN)+1) { String(cString:$0) } }
      if name.hasSuffix(".json") {
        names.append(name)
        guard names.count<=100 else { return .init(services:[],rejected:names.count,unavailable:true) }
      }
    }
    var services:[LocalService]=[],rejected=0
    for name in names.sorted() {
      do {
        let fd=openat(descriptor,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK)
        guard fd>=0 else { throw WorkServerSetupError.storage }
        let file=FileHandle(fileDescriptor:fd,closeOnDealloc:true);defer { try? file.close() }
        var info=stat()
        guard fstat(fd,&info)==0,info.st_uid==getuid(),info.st_nlink==1,info.st_mode&S_IFMT==S_IFREG,
          info.st_mode&0o077==0,info.st_size<=LocalResource.maximumBytes else { throw WorkServerSetupError.storage }
        let value=try LocalService.decode(file.read(upToCount:LocalResource.maximumBytes+1) ?? Data())
        guard name==value.id+".json" else { throw WorkServerSetupError.storage }
        services.append(value)
      } catch { rejected += 1 }
    }
    return .init(services:services.sorted { $0.title == $1.title ? $0.endpoint < $1.endpoint : $0.title < $1.title },rejected:rejected,unavailable:false)
  }
}

public struct LocalServiceHealth: Equatable, Sendable {
  public let reached: Bool
  public let walletAdministration: Bool
  public let ownerRegistrationRequired: Bool
  public init(reached: Bool, walletAdministration: Bool, ownerRegistrationRequired: Bool = false) {
    self.reached=reached;self.walletAdministration=walletAdministration;self.ownerRegistrationRequired=ownerRegistrationRequired
  }
  public var label: String {
    !reached ? "Not reachable · Refresh to check" : ownerRegistrationRequired ? "Running · Owner registration required" : walletAdministration ? "Running · Wallet access management" : "Running · No Wallet administration"
  }
  public static let unavailable=Self(reached:false,walletAdministration:false)
}

public enum LocalServiceProbe {
  public typealias Fetch = @Sendable (URL, String) async throws -> Data
  public static func check(endpoint: String, connection: WorkAccessConfiguration?, resourceID: String? = nil, instanceID: String? = nil, fetch: Fetch) async -> LocalServiceHealth {
    do {
      guard let origin=URL(string:endpoint) else { return .unavailable }
      let raw=try await fetch(origin,"/live")
      var strict=OwnerPlanJSON(raw,maximumBytes:16384);try strict.validate()
      guard let health=try JSONSerialization.jsonObject(with:raw) as? [String:Any],health["live"] as? Bool == true else { return .unavailable }
      guard (resourceID == nil || health["resource_id"] as? String == resourceID),
        (instanceID == nil || health["instance_id"] as? String == instanceID) else { return .unavailable }
      guard let connection else { return .init(reached:true,walletAdministration:false) }
      let mode=health["mode"] as? String ?? ""
      let unclaimed=mode == "owner-local-wallet-unclaimed"
      guard connection.origin == endpoint,
        ["lan-standing-access","owner-local-wallet-administration","owner-local-wallet-unclaimed"].contains(mode),
        !unclaimed || (health["owner_registered"] as? Bool == false && health["administration_enabled"] as? Bool == false)
      else { return .init(reached:true,walletAdministration:false) }
      let profile=try await fetch(origin,"/.well-known/devgraph-connection.json")
      var checked=OwnerPlanJSON(profile,maximumBytes:16384);try checked.validate()
      guard let value=try JSONSerialization.jsonObject(with:profile) as? [String:Any],
        value["receiver"] as? String == endpoint,value["issuer"] as? String == connection.issuer,
        value["name"] as? String == connection.name,let authority=value["authority"],
        try JSONDecoder().decode(ReadAuthorityPin.self,from:JSONSerialization.data(withJSONObject:authority)) == connection.authority else { return .unavailable }
      return .init(reached:true,walletAdministration:!unclaimed,ownerRegistrationRequired:unclaimed)
    } catch { return .unavailable }
  }
  public static func check(endpoint: String, connection: WorkAccessConfiguration?, resourceID: String? = nil, instanceID: String? = nil) async -> LocalServiceHealth {
    do {
      if let connection,
        let rpc = try? LocalAdminRPC.discover(configuration: connection) {
        guard (resourceID == nil || rpc.resourceID == resourceID),
          (instanceID == nil || rpc.instanceID == instanceID) else { return .unavailable }
        let response = try await rpc.call(operation: "inspect", body: Data("{}".utf8))
        guard response.status == 200,
          let value = try JSONSerialization.jsonObject(with: response.data) as? [String:Any],
          value["transport"] as? String == "local-secs-rpc",
          value["owner_registered"] as? Bool == true,
          value["credential_administration"] as? Bool == true else { return .unavailable }
        return .init(reached: true, walletAdministration: true)
      }
      let transport: PrivateTransport
      if connection?.network == .tailscale { transport=HostTailscaleConnection().transport() }
      else if let connection { transport=try PrivateTransport(workServer:connection) }
      else { let config=URLSessionConfiguration.ephemeral;config.connectionProxyDictionary=[:];transport=PrivateTransport(configuration:config) }
      return await check(endpoint:endpoint,connection:connection,resourceID:resourceID,instanceID:instanceID) { origin,path in
        try await transport.publicServiceMetadata(at:origin,path:path)
      }
    } catch { return .unavailable }
  }
}
#endif
