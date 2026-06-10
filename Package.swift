// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "fledge-plugin-http",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "fledge-http", targets: ["FledgeHttp"])
    ],
    dependencies: [],
    targets: [
        .executableTarget(
            name: "FledgeHttp",
            dependencies: [],
            path: "Sources/FledgeHttp",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
        .testTarget(
            name: "FledgeHttpTests",
            dependencies: ["FledgeHttp"],
            path: "Tests/FledgeHttpTests",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        )
    ]
)
