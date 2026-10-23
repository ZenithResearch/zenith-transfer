import CoreImage
import CoreGraphics
import Foundation

public enum RecoveryQRImage {
  /// Q error correction, integral scaling and a white quiet zone. Never render
  /// keys/passwords: callers provide only versioned encrypted-file frames.
  public static func render(_ frame: String) throws -> CGImage {
    guard frame.hasPrefix(RecoveryQR.prefix + ":"),
      frame.utf8.count <= RecoveryQR.maximumFrameCharacters,
      let generator = CIFilter(name: "CIQRCodeGenerator")
    else { throw RecoveryTransferError.invalidQR }
    generator.setValue(Data(frame.utf8), forKey: "inputMessage")
    generator.setValue("Q", forKey: "inputCorrectionLevel")
    guard let qr = generator.outputImage else { throw RecoveryTransferError.invalidQR }
    let bounds = qr.extent.insetBy(dx: -4, dy: -4)
    let white = CIImage(color: CIColor(red: 1, green: 1, blue: 1)).cropped(to: bounds)
    let image = qr.composited(over: white).transformed(by: CGAffineTransform(scaleX: 6, y: 6))
    guard let result = CIContext().createCGImage(image, from: image.extent) else {
      throw RecoveryTransferError.invalidQR
    }
    return result
  }
}
