import Benchmark
import Foundation
import Keychain
import KeychainLive

struct Credentials: Codable, Equatable, Sendable {
  var username: String
  var password: String
  var scopes: [String]
}

extension KeychainKey where Value == String {
  static let token = KeychainKey("auth.token")
}

extension KeychainKey where Value == Data {
  static let encryptionKey = KeychainKey("crypto.encryption-key")
}

extension KeychainKey where Value == Credentials {
  static let credentials = KeychainKey("user.credentials")
}

/// A bearer token the size of a typical JWT.
let token = String(repeating: "eyJhbGciOiJIUzI1NiJ9.", count: 40)
let keyBytes = Data((0..<32).map { UInt8($0) })
let credentials = Credentials(
  username: "ada@example.com",
  password: "correct horse battery staple",
  scopes: ["read", "write", "admin"]
)

/// The 100 accounts the enumeration benchmarks store, in no particular order.
let accounts = (0..<100).map { "token.\(($0 * 37) % 100)" }

/// A live client on a service of its own in the login keychain (`dataProtection: false`, as for an
/// unsigned binary), emptied after each live benchmark, so a run leaves nothing behind.
let live = KeychainClient.live(
  service: "swift-keychain.benchmarks.\(UUID().uuidString)",
  dataProtection: false
)

/// Whether to run the live benchmarks: the real keychain is slow and may be unavailable (CI).
let liveEnabled = ProcessInfo.processInfo.environment["SKIP_LIVE_KEYCHAIN_BENCHMARKS"] == nil

let benchmarks: @Sendable () -> Void = {
  Benchmark.defaultConfiguration = .init(
    metrics: [.wallClock, .cpuTotal, .mallocCountTotal, .peakMemoryResident, .retainCount],
    // Exact counts and microseconds, so a change of a few percent shows up in a comparison.
    timeUnits: .microseconds,
    units: [.mallocCountTotal: .count, .retainCount: .count],
    maxDuration: .seconds(2),
    maxIterations: 1_000
  )
  let perOperation = Benchmark.Configuration(timeUnits: .nanoseconds, scalingFactor: .kilo)

  // MARK: Typed keys

  Benchmark("Encode and decode, String key", configuration: perOperation) { benchmark in
    for _ in benchmark.scaledIterations {
      blackHole(try KeychainKey.token.decode(KeychainKey.token.encode(token)))
    }
  }

  Benchmark("Encode and decode, Data key", configuration: perOperation) { benchmark in
    for _ in benchmark.scaledIterations {
      blackHole(try KeychainKey.encryptionKey.decode(KeychainKey.encryptionKey.encode(keyBytes)))
    }
  }

  Benchmark("Encode and decode, Codable key", configuration: perOperation) { benchmark in
    for _ in benchmark.scaledIterations {
      blackHole(try KeychainKey.credentials.decode(KeychainKey.credentials.encode(credentials)))
    }
  }

  // MARK: Secret

  let tokenA = Secret(token)
  let tokenB = Secret(String(token.reversed().reversed()))
  let bytesA = Secret(keyBytes)
  let bytesB = Secret(Data(keyBytes))

  Benchmark("Secret ==, String", configuration: perOperation) { benchmark in
    for _ in benchmark.scaledIterations { blackHole(tokenA == tokenB) }
  }

  Benchmark("Secret ==, Data", configuration: perOperation) { benchmark in
    for _ in benchmark.scaledIterations { blackHole(bytesA == bytesB) }
  }

  // MARK: In-memory client

  Benchmark("In-memory save and load, String", configuration: perOperation) { benchmark in
    let keychain = KeychainClient.inMemory()
    for _ in benchmark.scaledIterations {
      try await keychain.save(Secret(token), for: .token)
      blackHole(try await keychain.load(for: .token))
    }
  }

  Benchmark("In-memory save and load, Codable", configuration: perOperation) { benchmark in
    let keychain = KeychainClient.inMemory()
    for _ in benchmark.scaledIterations {
      try await keychain.save(Secret(credentials), for: .credentials)
      blackHole(try await keychain.load(for: .credentials))
    }
  }

  Benchmark("In-memory loadIfPresent, missing", configuration: perOperation) { benchmark in
    let keychain = KeychainClient.inMemory()
    for _ in benchmark.scaledIterations {
      blackHole(try await keychain.loadIfPresent(for: .token))
    }
  }

  Benchmark("In-memory exists", configuration: perOperation) { benchmark in
    let keychain = try KeychainClient.inMemory { try KeychainEntry(Secret(token), for: .token) }
    for _ in benchmark.scaledIterations { blackHole(await keychain.exists(for: .token)) }
  }

  Benchmark("In-memory prefill, 100 entries") { benchmark in
    blackHole(
      try KeychainClient.inMemory {
        for account in accounts { try KeychainEntry(Secret(token), for: KeychainKey<String>(account)) }
      }
    )
  }

  Benchmark("In-memory keys, 100 items") { benchmark in
    let keychain = try KeychainClient.inMemory {
      for account in accounts { try KeychainEntry(Secret(token), for: KeychainKey<String>(account)) }
    }
    benchmark.startMeasurement()
    for _ in 0..<100 {
      blackHole(try await keychain.keys { KeychainKey<String>($0) })
    }
  }

  Benchmark("In-memory stream, first value", configuration: perOperation) { benchmark in
    let keychain = try KeychainClient.inMemory { try KeychainEntry(Secret(token), for: .token) }
    for _ in benchmark.scaledIterations {
      var values = keychain.stream(for: .token).makeAsyncIterator()
      blackHole(await values.next())
    }
  }

  // MARK: Live keychain (login keychain, a service of its own)

  guard liveEnabled else { return }
  let liveConfiguration = Benchmark.Configuration(
    maxDuration: .seconds(2),
    maxIterations: 200,
    teardown: { try await live.deleteAll() }
  )
  let prefilled = Benchmark.Configuration(
    maxDuration: .seconds(2),
    maxIterations: 200,
    setup: { try await live.save(Secret(token), for: .token) },
    teardown: { try await live.deleteAll() }
  )

  Benchmark("Live save, String (update)", configuration: prefilled) { _ in
    try await live.save(Secret(token), for: .token)
  }

  Benchmark("Live load, String", configuration: prefilled) { _ in
    blackHole(try await live.load(for: .token))
  }

  Benchmark("Live exists", configuration: prefilled) { _ in
    blackHole(await live.exists(for: .token))
  }

  Benchmark("Live attributes", configuration: prefilled) { _ in
    blackHole(try await live.attributes(for: .token))
  }

  Benchmark("Live save and delete", configuration: liveConfiguration) { _ in
    try await live.save(Secret(token), for: .token)
    try await live.delete(for: .token)
  }
}
