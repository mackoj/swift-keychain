#if os(macOS)
  import CryptoKit
  import Foundation
  import Keychain
  import KeychainLive
  import Testing

  // These tests use the real login keychain. `swift test` binaries are unsigned, so they use the
  // file-based keychain (`dataProtection: false`); each test gets its own service and cleans up.
  // Set SKIP_LIVE_KEYCHAIN_TESTS=1 where no keychain is available.
  let liveTestsEnabled = ProcessInfo.processInfo.environment["SKIP_LIVE_KEYCHAIN_TESTS"] == nil

  extension KeychainKey where Value == String {
    fileprivate static let token = KeychainKey("token")
    fileprivate static let other = KeychainKey("other")
    fileprivate static let renamed = KeychainKey("renamed")
  }

  /// A live keychain on a fresh service, emptied after `body` whether it threw or not.
  func withLiveKeychain(_ body: (KeychainClient) async throws -> Void) async throws {
    let keychain = KeychainClient.live(
      service: "swift-keychain.tests.\(UUID().uuidString)",
      dataProtection: false
    )
    do {
      try await body(keychain)
    } catch {
      try? await keychain.deleteAll()
      throw error
    }
    try await keychain.deleteAll()
  }

  @Suite(.enabled(if: liveTestsEnabled))
  struct KeychainLiveTests {
    @Test func saveLoadUpdateDelete() async throws {
      try await withLiveKeychain { keychain in
        try await keychain.save(Secret("one"), for: .token)
        #expect(try await keychain.load(for: .token) == Secret("one"))

        try await keychain.save(Secret("two"), for: .token)
        #expect(try await keychain.load(for: .token) == Secret("two"))

        try await keychain.delete(for: .token)
        try await keychain.delete(for: .token)
        #expect(try await keychain.loadIfPresent(for: .token) == nil)
      }
    }

    @Test func existsAndKeys() async throws {
      try await withLiveKeychain { keychain in
        #expect(await keychain.exists(for: .token) == false)

        try await keychain.save(Secret("one"), for: .token)
        try await keychain.save(Secret("two"), for: .other)

        #expect(await keychain.exists(for: .token))
        #expect(try await keychain.keys() == ["other", "token"])
      }
    }

    @Test func deleteAllIsScopedToTheService() async throws {
      try await withLiveKeychain { mine in
        try await withLiveKeychain { theirs in
          try await mine.save(Secret("mine"), for: .token)
          try await theirs.save(Secret("theirs"), for: .token)

          try await mine.deleteAll()

          #expect(try await mine.keys() == [])
          #expect(try await theirs.load(for: .token) == Secret("theirs"))
        }
      }
    }

    @Test func renameMovesTheItemAndReplacesTheTarget() async throws {
      try await withLiveKeychain { keychain in
        try await keychain.save(Secret("one"), for: .token)
        try await keychain.save(Secret("old"), for: .renamed)

        try await keychain.rename(.token, to: .renamed)

        #expect(try await keychain.keys() == ["renamed"])
        #expect(try await keychain.load(for: .renamed) == Secret("one"))
        await #expect(throws: KeychainError.itemNotFound) {
          try await keychain.rename(.token, to: .renamed)
        }
      }
    }

    @Test func attributesAreSavedReadAndUpdatedWithoutTheData() async throws {
      try await withLiveKeychain { keychain in
        #expect(try await keychain.attributes(for: .token) == nil)
        try await keychain.save(
          Secret("one"),
          for: .token,
          attributes: .init(label: "Token", comment: "a\nb")
        )
        #expect(
          try await keychain.attributes(for: .token) == .init(label: "Token", comment: "a\nb")
        )

        try await keychain.updateAttributes(.init(comment: "c"), for: .token)
        #expect(try await keychain.attributes(for: .token) == .init(comment: "c"))
        #expect(try await keychain.load(for: .token) == Secret("one"))

        try await keychain.save(Secret("two"), for: .token)
        #expect(try await keychain.attributes(for: .token) == .init(comment: "c"))
        try await keychain.save(Secret("three"), for: .token, attributes: .init(label: "L"))
        #expect(try await keychain.attributes(for: .token) == .init(label: "L"))

        try await keychain.rename(.token, to: .renamed)
        #expect(try await keychain.attributes(for: .renamed) == .init(label: "L"))
        await #expect(throws: KeychainError.itemNotFound) {
          try await keychain.updateAttributes(.init(), for: .token)
        }
      }
    }

    @Test func streamYieldsCurrentValueThenChanges() async throws {
      try await withLiveKeychain { keychain in
        try await keychain.save(Secret("one"), for: .token)
        var values = keychain.stream(for: .token).makeAsyncIterator()

        #expect(await values.next() == Secret("one"))
        try await keychain.save(Secret("two"), for: .token)
        #expect(await values.next() == Secret("two"))
        try await keychain.delete(for: .token)
        #expect(await values.next() == .some(nil))
      }
    }
  }

  @Suite(.enabled(if: liveTestsEnabled && SecureEnclave.isAvailable))
  struct SecureEnclaveLiveTests {
    let enclave = SecureEnclaveClient.live(
      service: "swift-keychain.tests.\(UUID().uuidString)",
      dataProtection: false
    )

    @Test func signAndVerify() async throws {
      let key = SecureEnclaveKey<Signing>("identity")
      let message = Data("hello".utf8)

      let created = try await enclave.createKey(key)
      let signature = try await enclave.sign(message, with: key)
      let loaded = try await enclave.publicKey(for: key)
      try await enclave.deleteKey(key)

      #expect(created.isValidSignature(signature, for: message))
      #expect(loaded == created)
    }

    @Test func keyAgreement() async throws {
      let key = SecureEnclaveKey<KeyAgreement>("agreement")
      let peer = P256.KeyAgreement.PrivateKey()

      let ours = try await enclave.createKey(key)
      let secret = try await enclave.sharedSecret(
        with: SecureEnclavePublicKey(x963Representation: peer.publicKey.x963Representation),
        using: key
      )
      try await enclave.deleteKey(key)

      let theirs = try peer.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: ours.x963Representation)
      )
      #expect(secret == Secret(theirs.withUnsafeBytes { Data($0) }))
    }
  }
#endif
