// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "ClawDefenderMenuBar",
    platforms: [
        .macOS(.v13),
    ],
    targets: [
        .executableTarget(
            name: "ClawDefenderMenuBar",
            path: "Sources/ClawDefenderMenuBar"
        ),
    ]
)
