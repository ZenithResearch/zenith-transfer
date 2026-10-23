import Foundation

/// User-selected route. Private networking never grants Work authority.
public enum WorkNetwork: String, Codable, Sendable, Hashable {
  case tailscale
  case lan
  case local
}

public struct WorkConnectionFailure: LocalizedError, Sendable {
  let code: URLError.Code
  let network: WorkNetwork?
  public init(code: URLError.Code, network: WorkNetwork?) {
    self.code = code
    self.network = network
  }
  public var errorDescription: String? {
    if code == .secureConnectionFailed || code == .serverCertificateUntrusted
      || code == .serverCertificateHasBadDate || code == .serverCertificateHasUnknownRoot
      || code == .serverCertificateNotYetValid {
      return "The server’s secure connection could not be verified. Contact the server owner."
    }
    if code == .cancelled { return "Connection cancelled." }
    if network == .tailscale {
      return "Can’t reach your work server through Tailscale. Check the private connection and server address, then try again."
    }
    if network == .lan {
      return "Can’t reach your work server on this network. Join the same Wi-Fi as your server and allow Local Network access for Zenith in Settings, then try again."
    }
    if network == .local { return "Can’t reach DevGraph on this Mac. Check that its Wallet administration service is running." }
    return "Can’t reach your work server. Check your internet connection and try again."
  }
}
