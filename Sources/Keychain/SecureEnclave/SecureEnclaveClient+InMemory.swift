#if canImport(CryptoKit)
  import CryptoKit
  import Foundation

  extension SecureEnclaveClient {
    /// A Secure Enclave stand-in backed by software P-256 keys held in memory.
    /// Each call returns an independent store. Signatures and shared secrets are real, so they
    /// verify against the returned public keys.
    ///
    /// - Parameter authenticate: Simulates the prompt for keys with an authentication gate.
    public static func inMemory(
      authenticate: @escaping Authenticator = { _, _ in true }
    ) -> SecureEnclaveClient {
      let storage = InMemorySecureEnclave(authenticate: authenticate)
      return SecureEnclaveClient(
        isAvailable: { true },
        createKey: { key in await storage.createKey(key) },
        publicKey: { key in try await storage.publicKey(key) },
        deleteKey: { key in await storage.deleteKey(key) },
        sign: { data, key, context in try await storage.sign(data, key: key, context: context) },
        sharedSecret: { publicKey, key, context in
          try await storage.sharedSecret(publicKey, key: key, context: context)
        }
      )
    }

    public static var previewValue: SecureEnclaveClient { .inMemory() }
  }

  private actor InMemorySecureEnclave {
    private struct Address: Hashable {
      let tag: String
      let kind: SecureEnclaveKeyKind

      init(_ key: SecureEnclaveKeyDescriptor) {
        self.tag = key.tag
        self.kind = key.kind
      }
    }

    private struct Item {
      let rawPrivateKey: Data
      let authentication: KeychainAuthentication
    }

    private var items: [Address: Item] = [:]
    private let authenticate: Authenticator

    init(authenticate: @escaping Authenticator) {
      self.authenticate = authenticate
    }

    func createKey(_ key: SecureEnclaveKeyDescriptor) -> SecureEnclavePublicKey {
      let (rawPrivateKey, publicKey) =
        switch key.kind {
        case .signing:
          P256.Signing.PrivateKey().withRawAndPublic()
        case .keyAgreement:
          P256.KeyAgreement.PrivateKey().withRawAndPublic()
        }
      items[Address(key)] = Item(rawPrivateKey: rawPrivateKey, authentication: key.authentication)
      return publicKey
    }

    func publicKey(_ key: SecureEnclaveKeyDescriptor) throws -> SecureEnclavePublicKey {
      let item = try item(key)
      return switch key.kind {
      case .signing:
        try SecureEnclavePublicKey(
          x963Representation: P256.Signing.PrivateKey(rawRepresentation: item.rawPrivateKey)
            .publicKey.x963Representation
        )
      case .keyAgreement:
        try SecureEnclavePublicKey(
          x963Representation: P256.KeyAgreement.PrivateKey(rawRepresentation: item.rawPrivateKey)
            .publicKey.x963Representation
        )
      }
    }

    func deleteKey(_ key: SecureEnclaveKeyDescriptor) {
      items[Address(key)] = nil
    }

    func sign(_ data: Data, key: SecureEnclaveKeyDescriptor, context: AuthContext?) async throws
      -> Data
    {
      guard key.kind == .signing else { throw KeychainError.invalidKey }
      let item = try await authorizedItem(key, context: context)
      let privateKey = try P256.Signing.PrivateKey(rawRepresentation: item.rawPrivateKey)
      return try privateKey.signature(for: data).derRepresentation
    }

    func sharedSecret(
      _ publicKey: SecureEnclavePublicKey,
      key: SecureEnclaveKeyDescriptor,
      context: AuthContext?
    ) async throws -> Secret<Data> {
      guard key.kind == .keyAgreement else { throw KeychainError.invalidKey }
      let item = try await authorizedItem(key, context: context)
      let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: item.rawPrivateKey)
      let peer: P256.KeyAgreement.PublicKey
      do {
        peer = try P256.KeyAgreement.PublicKey(x963Representation: publicKey.x963Representation)
      } catch {
        throw KeychainError.invalidKey
      }
      let secret = try privateKey.sharedSecretFromKeyAgreement(with: peer)
      return Secret(secret.withUnsafeBytes { Data($0) })
    }

    private func item(_ key: SecureEnclaveKeyDescriptor) throws -> Item {
      guard let item = items[Address(key)] else { throw KeychainError.itemNotFound }
      return item
    }

    private func authorizedItem(_ key: SecureEnclaveKeyDescriptor, context: AuthContext?)
      async throws -> Item
    {
      let item = try item(key)
      if item.authentication != .none {
        guard await authenticate(item.authentication, context) else {
          throw KeychainError.authenticationFailed
        }
      }
      return item
    }
  }

  extension P256.Signing.PrivateKey {
    fileprivate func withRawAndPublic() -> (Data, SecureEnclavePublicKey) {
      (rawRepresentation, SecureEnclavePublicKey(x963Representation: publicKey.x963Representation))
    }
  }

  extension P256.KeyAgreement.PrivateKey {
    fileprivate func withRawAndPublic() -> (Data, SecureEnclavePublicKey) {
      (rawRepresentation, SecureEnclavePublicKey(x963Representation: publicKey.x963Representation))
    }
  }

  // MARK: - Verification

  extension SecureEnclavePublicKey {
    /// Whether `signature` (DER-encoded ECDSA) signs the SHA-256 digest of `data` with this key.
    public func isValidSignature(_ signature: Data, for data: Data) -> Bool {
      guard
        let publicKey = try? P256.Signing.PublicKey(x963Representation: x963Representation),
        let signature = try? P256.Signing.ECDSASignature(derRepresentation: signature)
      else { return false }
      return publicKey.isValidSignature(signature, for: data)
    }
  }
#endif
