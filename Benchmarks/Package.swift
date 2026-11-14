// swift-tools-version: 6.1
import PackageDescription

// swift-keychain's benchmarks, on ordo-one/package-benchmark (https://www.swift.org/blog/benchmarks/).
// A separate package so the benchmark dependency never reaches the library's clients. Run from the
// repository root: `xcrun swift package --package-path Benchmarks benchmark`.
let package = Package(
  name: "Benchmarks",
  platforms: [.macOS(.v15)],
  dependencies: [
    .package(name: "swift-keychain", path: ".."),
    .package(url: "https://github.com/ordo-one/package-benchmark.git", from: "1.38.0"),
  ],
  targets: [
    .executableTarget(
      name: "KeychainBenchmarks",
      dependencies: [
        .product(name: "Benchmark", package: "package-benchmark"),
        .product(name: "Keychain", package: "swift-keychain"),
        .product(name: "KeychainLive", package: "swift-keychain"),
      ],
      path: "Benchmarks/KeychainBenchmarks",
      plugins: [
        .plugin(name: "BenchmarkPlugin", package: "package-benchmark")
      ]
    ),
    // Reads two `benchmark --format markdown` outputs and prints each benchmark's p50 before and after.
    .executableTarget(name: "p50", path: "Tools/P50"),
    // Reads an exported Time Profiler table and prints the hottest functions (scripts/profile.sh).
    .executableTarget(name: "hotspots", path: "Tools/Hotspots"),
  ]
)
