// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ClawDefenderNetwork",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .executable(
            name: "ClawDefenderNetwork",
            targets: ["ClawDefenderNetwork"]
        ),
    ],
    targets: [
        .executableTarget(
            name: "ClawDefenderNetwork",
            path: "Sources/ClawDefenderNetwork",
            linkerSettings: [
                .linkedFramework("NetworkExtension"),
                .linkedFramework("SystemExtensions"),
            ]
        ),
    ]
)
