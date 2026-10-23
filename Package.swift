// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "ZenithKit", platforms: [.iOS(.v17), .macOS(.v13)], products: [.library(name: "ZenithKit", targets: ["ZenithKit"]), .executable(name: "ZenithTransfer", targets: ["ZenithTransfer"])], targets: [
    .binaryTarget(name: "CastaliaWallet", path: "Artifacts/CastaliaWallet.xcframework"),
    .target(name: "ZenithKit", dependencies: ["CastaliaWallet"], linkerSettings: [.linkedLibrary("sqlite3")]),
    .executableTarget(name: "ZenithTransfer", dependencies: ["ZenithKit"], resources: [.copy("Resources")]),
    .testTarget(name: "ZenithKitTests", dependencies: ["ZenithKit"], resources: [.process("Fixtures")]),
    .testTarget(name: "ZenithTransferTests", dependencies: ["ZenithTransfer", "ZenithKit"], resources: [.copy("Fixtures")])
])
