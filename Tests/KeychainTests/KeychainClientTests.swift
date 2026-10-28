import Dependencies
import DependenciesTestSupport
import Foundation
import Keychain
import Testing

struct KeychainClientTests {
  @Test func stringRoundTrip() async throws {
    let keychain = KeychainClient.inMemory()

    try await keychain.save(Secret("t0k3n"), for: .authToken)

    #expect(try await keychain.load(for: .authToken) == Secret("t0k3n"))
  }

  @Test func codableRoundTrip() async throws {
    let keychain = KeychainClient.inMemory()
    let credentials = Credentials(username: "ada", pin: "1815")

    try await keychain.save(Secret(credentials), for: .credentials)

    #expect(try await keychain.load(for: .credentials) == Secret(credentials))
  }

  @Test func saveReplacesTheExistingValue() async throws {
    let keychain = KeychainClient.inMemory()

    try await keychain.save(Secret("old"), for: .authToken)
    try await keychain.save(Secret("new"), for: .authToken)

    #expect(try await keychain.load(for: .authToken) == Secret("new"))
  }

  @Test func loadOfAMissingItemThrowsItemNotFound() async throws {
    let keychain = KeychainClient.inMemory()

    await #expect(throws: KeychainError.itemNotFound) {
      try await keychain.load(for: .authToken)
    }
    #expect(try await keychain.loadIfPresent(for: .authToken) == nil)
  }

  @Test func undecodableBytesThrowDecodingFailed() async throws {
    let keychain = KeychainClient.inMemory()

    try await keychain.save(Secret(Data([0xFF, 0xFE])), "auth.token", .afterFirstUnlock, .none)

    await #expect(throws: KeychainError.decodingFailed) {
      try await keychain.load(for: .authToken)
    }
  }

  @Test func deleteIsIdempotent() async throws {
    let keychain = try KeychainClient.inMemory {
      try KeychainEntry(Secret("t0k3n"), for: .authToken)
    }

    try await keychain.delete(for: .authToken)
    try await keychain.delete(for: .authToken)

    #expect(await keychain.exists(for: .authToken) == false)
  }

  @Test func deleteAllAndKeys() async throws {
    let keychain = try KeychainClient.inMemory {
      try KeychainEntry(Secret("t0k3n"), for: .authToken)
      try KeychainEntry(Secret(Data([1])), for: .encryptionKey)
    }

    #expect(try await keychain.keys() == ["auth.token", "crypto.encryption-key"])
    try await keychain.deleteAll()
    #expect(try await keychain.keys() == [])
  }

  @Test func prefilledItemsKeepTheirAuthenticationGate() async throws {
    let keychain = try KeychainClient.inMemory(authenticate: { _, _ in false }) {
      try KeychainEntry(Secret("open sesame"), for: .vaultPassword)
    }

    #expect(await keychain.exists(for: .vaultPassword))
    await #expect(throws: KeychainError.authenticationFailed) {
      try await keychain.load(for: .vaultPassword)
    }
  }

  @Test func authenticatorReceivesTheGate() async throws {
    let gates = LockIsolated<[KeychainAuthentication]>([])
    let keychain = KeychainClient.inMemory(authenticate: { gate, _ in
      gates.withValue { $0.append(gate) }
      return true
    })

    try await keychain.save(Secret("open sesame"), for: .vaultPassword)
    try await keychain.save(Secret("t0k3n"), for: .authToken)
    _ = try await keychain.load(for: .vaultPassword)
    _ = try await keychain.load(for: .authToken)

    #expect(gates.value == [.biometricOrPasscode])
  }

  @Test func streamYieldsCurrentValueThenChanges() async throws {
    let keychain = KeychainClient.inMemory()
    try await keychain.save(Secret("one"), for: .authToken)
    var values = keychain.stream(for: .authToken).makeAsyncIterator()

    #expect(await values.next() == Secret("one"))
    try await keychain.save(Secret("two"), for: .authToken)
    #expect(await values.next() == Secret("two"))
    try await keychain.delete(for: .authToken)
    #expect(await values.next() == .some(nil))
  }

  @Test func streamNeverRevealsAGatedValue() async throws {
    let keychain = try KeychainClient.inMemory {
      try KeychainEntry(Secret("open sesame"), for: .vaultPassword)
    }
    var values = keychain.stream(for: .vaultPassword).makeAsyncIterator()

    // The gated first value is skipped; the stream starts with the next change.
    try await keychain.delete(for: .vaultPassword)
    #expect(await values.next() == .some(nil))
  }

  @Test func noopStoresNothing() async throws {
    let keychain = KeychainClient.noop

    try await keychain.save(Secret("t0k3n"), for: .authToken)

    await #expect(throws: KeychainError.itemNotFound) {
      try await keychain.load(for: .authToken)
    }
  }
}

@Suite(.dependencies { $0.keychain = .inMemory() })
struct KeychainDependencyTests {
  struct Session {
    @Dependency(\.keychain) var keychain

    func logIn(token: String) async throws {
      try await keychain.save(Secret(token), for: .authToken)
    }

    func bearer() async throws -> String {
      "Bearer \(try await keychain.load(for: .authToken).exposeSecret())"
    }
  }

  @Test func featureUsesTheOverriddenKeychain() async throws {
    let session = Session()

    try await session.logIn(token: "t0k3n")

    #expect(try await session.bearer() == "Bearer t0k3n")
  }

  @Test func overrideASingleEndpoint() async throws {
    let bearer = try await withDependencies {
      $0.keychain.load = { @Sendable _, _ in Secret(Data("stubbed".utf8)) }
    } operation: {
      try await Session().bearer()
    }

    #expect(bearer == "Bearer stubbed")
  }

  @Test func unimplementedEndpointFailsTheTest() async throws {
    await withKnownIssue {
      try await withDependencies {
        $0.keychain = KeychainClient()
      } operation: {
        _ = try await Session().bearer()
      }
    }
  }
}
