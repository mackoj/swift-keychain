#if canImport(CryptoKit)
  import CryptoKit
  import Foundation
  import Keychain
  import Testing

  struct SecureEnclaveClientTests {
    @Test func signatureVerifiesWithThePublicKey() async throws {
      let enclave = SecureEnclaveClient.inMemory()
      let message = Data("approve payment #42".utf8)

      let publicKey = try await enclave.createKey(.deviceIdentity)
      let signature = try await enclave.sign(message, with: .deviceIdentity)

      #expect(publicKey.isValidSignature(signature, for: message))
      #expect(!publicKey.isValidSignature(signature, for: Data("tampered".utf8)))
    }

    @Test func publicKeyIsStable() async throws {
      let enclave = SecureEnclaveClient.inMemory()

      let created = try await enclave.publicKeyCreatingIfNeeded(for: .deviceIdentity)
      let loaded = try await enclave.publicKeyCreatingIfNeeded(for: .deviceIdentity)

      #expect(created == loaded)
      #expect(created.x963Representation.count == 65)
    }

    @Test func createKeyReplacesTheExistingKey() async throws {
      let enclave = SecureEnclaveClient.inMemory()

      let first = try await enclave.createKey(.deviceIdentity)
      let second = try await enclave.createKey(.deviceIdentity)

      #expect(first != second)
      #expect(try await enclave.publicKey(for: .deviceIdentity) == second)
    }

    @Test func deletedKeyIsGone() async throws {
      let enclave = SecureEnclaveClient.inMemory()
      _ = try await enclave.createKey(.deviceIdentity)

      try await enclave.deleteKey(.deviceIdentity)
      try await enclave.deleteKey(.deviceIdentity)

      await #expect(throws: KeychainError.itemNotFound) {
        try await enclave.publicKey(for: .deviceIdentity)
      }
    }

    @Test func keyAgreementMatchesThePeer() async throws {
      let enclave = SecureEnclaveClient.inMemory()
      let peer = P256.KeyAgreement.PrivateKey()

      let ours = try await enclave.createKey(.sessionAgreement)
      let secret = try await enclave.sharedSecret(
        with: SecureEnclavePublicKey(x963Representation: peer.publicKey.x963Representation),
        using: .sessionAgreement
      )

      let theirs = try peer.sharedSecretFromKeyAgreement(
        with: P256.KeyAgreement.PublicKey(x963Representation: ours.x963Representation)
      )
      #expect(secret == Secret(theirs.withUnsafeBytes { Data($0) }))
    }

    @Test func malformedPeerKeyThrowsInvalidKey() async throws {
      let enclave = SecureEnclaveClient.inMemory()
      _ = try await enclave.createKey(.sessionAgreement)

      await #expect(throws: KeychainError.invalidKey) {
        try await enclave.sharedSecret(
          with: SecureEnclavePublicKey(x963Representation: Data([0x04, 0x01])),
          using: .sessionAgreement
        )
      }
    }

    @Test func refusedAuthenticationThrows() async throws {
      let enclave = SecureEnclaveClient.inMemory(authenticate: { gate, _ in gate == .none })
      _ = try await enclave.createKey(.paymentApproval)
      _ = try await enclave.createKey(.deviceIdentity)

      await #expect(throws: KeychainError.authenticationFailed) {
        try await enclave.sign(Data(), with: .paymentApproval)
      }
      _ = try await enclave.sign(Data(), with: .deviceIdentity)
    }

    @Test func signingAndAgreementKeysMayShareATag() async throws {
      let enclave = SecureEnclaveClient.inMemory()

      let signing = try await enclave.createKey(SecureEnclaveKey<Signing>("shared"))
      let agreement = try await enclave.createKey(SecureEnclaveKey<KeyAgreement>("shared"))

      #expect(signing != agreement)
    }

    @Test func testValueIsUnavailableAndUnimplemented() async throws {
      let enclave = SecureEnclaveClient.testValue

      await withKnownIssue {
        #expect(enclave.isAvailable() == false)
        _ = try await enclave.createKey(.deviceIdentity)
      }
    }
  }
#endif
