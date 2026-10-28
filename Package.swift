// swift-tools-version: 6.2
import PackageDescription

let swiftSettings: [SwiftSetting] = [
  .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
  .enableUpcomingFeature("InferIsolatedConformances"),
  .enableUpcomingFeature("ExistentialAny"),
]

let package = Package(
  name: "swift-keychain",
  platforms: [
    .iOS(.v16),
    .macOS(.v13),
    .tvOS(.v16),
    .watchOS(.v9),
    .visionOS(.v1),
  ],
  products: [
    .library(name: "Keychain", targets: ["Keychain"]),
    .library(name: "KeychainLive", targets: ["KeychainLive"]),
  ],
  dependencies: [
    .package(url: "https://github.com/pointfreeco/swift-dependencies", from: "1.9.0")
  ],
  targets: [
    // Interface: the clients, typed keys, `Secret`, errors and in-memory test doubles.
    // Never imports Security, so feature modules and their tests don't link it.
    .target(
      name: "Keychain",
      dependencies: [
        .product(name: "Dependencies", package: "swift-dependencies"),
        .product(name: "DependenciesMacros", package: "swift-dependencies"),
      ],
      swiftSettings: swiftSettings
    ),
    // Live implementations backed by Security.framework and CryptoKit. Link from the app target only.
    .target(
      name: "KeychainLive",
      dependencies: [
        "Keychain",
        .product(name: "Dependencies", package: "swift-dependencies"),
      ],
      swiftSettings: swiftSettings
    ),
    .testTarget(
      name: "KeychainTests",
      dependencies: [
        "Keychain",
        .product(name: "DependenciesTestSupport", package: "swift-dependencies"),
      ],
      swiftSettings: swiftSettings
    ),
    .testTarget(
      name: "KeychainLiveTests",
      dependencies: [
        "Keychain",
        "KeychainLive",
      ],
      swiftSettings: swiftSettings
    ),
  ]
)
