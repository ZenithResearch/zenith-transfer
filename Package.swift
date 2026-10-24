// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "ZenithKit", platforms: [.iOS(.v17), .macOS(.v13)], products: [.library(name: "ZenithKit", targets: ["ZenithKit"]), .library(name: "CastaliaCustody", targets: ["CastaliaCustody"]), .executable(name: "ZenithTransfer", targets: ["ZenithTransfer"])], targets: [
    .target(name: "CastaliaSignerProtocol"),
    .target(name: "CastaliaSignerTransport", dependencies: ["CastaliaSignerProtocol"]),
    .target(name: "CastaliaSignerStorage", dependencies: ["CastaliaSignerProtocol"], linkerSettings: [.linkedLibrary("sqlite3")]),
    .binaryTarget(name: "CastaliaWallet", path: "Artifacts/CastaliaWallet.xcframework"),
    .target(name: "ZenithKit", dependencies: ["CastaliaSignerProtocol"]),
    .target(name: "CastaliaCustody", dependencies: ["ZenithKit", "CastaliaWallet"], linkerSettings: [.linkedLibrary("sqlite3")]),
    .executableTarget(name: "ZenithTransfer", dependencies: ["ZenithKit", "CastaliaCustody"], resources: [.copy("Resources")]),
    .testTarget(name: "ZenithKitTests", dependencies: ["ZenithKit", "CastaliaCustody", "CastaliaSignerProtocol", "CastaliaSignerStorage", "CastaliaSignerTransport"], resources: [.process("Fixtures")]),
    .testTarget(name: "ZenithTransferTests", dependencies: ["ZenithTransfer", "ZenithKit", "CastaliaCustody"], resources: [.copy("Fixtures")])
])
