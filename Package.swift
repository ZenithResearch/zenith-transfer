// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "ZenithKit", platforms: [.iOS(.v17), .macOS(.v13)], products: [.library(name: "ZenithKit", targets: ["ZenithKit"]), .executable(name: "ZenithTransfer", targets: ["ZenithTransfer"])], targets: [
    .target(name: "CastaliaSignerProtocol"),
    .target(name: "CastaliaSignerTransport", dependencies: ["CastaliaSignerProtocol"]),
    .target(name: "CastaliaSignerStorage", dependencies: ["CastaliaSignerProtocol"], linkerSettings: [.linkedLibrary("sqlite3")]),
    .binaryTarget(name: "CastaliaWallet", path: "Artifacts/CastaliaWallet.xcframework"),
    .target(name: "ZenithKit", dependencies: ["CastaliaWallet", "CastaliaSignerProtocol"], linkerSettings: [.linkedLibrary("sqlite3")]),
    .executableTarget(name: "ZenithTransfer", dependencies: ["ZenithKit"], resources: [.copy("Resources")]),
    .testTarget(name: "ZenithKitTests", dependencies: ["ZenithKit", "CastaliaSignerProtocol", "CastaliaSignerStorage", "CastaliaSignerTransport"], resources: [.process("Fixtures")]),
    .testTarget(name: "ZenithTransferTests", dependencies: ["ZenithTransfer", "ZenithKit"], resources: [.copy("Fixtures")])
])
