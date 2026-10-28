#if canImport(Security) && canImport(CryptoKit)
  import CryptoKit
  import Dependencies
  import Foundation
  import Keychain
  import Security

  #if canImport(LocalAuthentication)
    import LocalAuthentication
  #endif

  extension SecureEnclaveClient: DependencyKey {
    /// The device's Secure Enclave, with key handles kept in the main bundle's service.
    public static let liveValue = SecureEnclaveClient.live(
      service: Bundle.main.bundleIdentifier ?? "swift-keychain"
    )

    /// A client for the device's Secure Enclave.
    ///
    /// Each private key is created inside the enclave and never leaves it. The keychain keeps
    /// the key's encrypted handle (CryptoKit's `dataRepresentation`) as a generic password in
    /// the service `"<service>.secure-enclave"`, so `KeychainClient.deleteAll()` on `service`
    /// leaves keys alone (D-6).
    ///
    /// The parameters are those of `KeychainClient.live(service:accessGroup:dataProtection:)`.
    public static func live(
      service: String,
      accessGroup: String? = nil,
      dataProtection: Bool = true
    ) -> SecureEnclaveClient {
      let store = KeychainStore(
        service: "\(service).secure-enclave",
        accessGroup: accessGroup,
        dataProtection: dataProtection
      )
      return SecureEnclaveClient(
        isAvailable: { SecureEnclave.isAvailable },
        createKey: { key in
          guard SecureEnclave.isAvailable else { throw KeychainError.secureEnclaveUnavailable }
          let control = try accessControl(
            key.accessibility.keychainAccessibility,
            key.authentication,
            extraFlags: .privateKeyUsage
          )
          let (handle, publicKey) = try enclaveCall {
            switch key.kind {
            case .signing:
              let privateKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: control)
              return (privateKey.dataRepresentation, privateKey.publicKey.x963Representation)
            case .keyAgreement:
              let privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                accessControl: control
              )
              return (privateKey.dataRepresentation, privateKey.publicKey.x963Representation)
            }
          }
          try await store.save(
            handle,
            key: key.account,
            accessibility: key.accessibility.keychainAccessibility,
            authentication: .none
          )
          return SecureEnclavePublicKey(x963Representation: publicKey)
        },
        publicKey: { key in
          let handle = try await store.load(key: key.account, context: nil)
          // Reading the public key from the handle doesn't use the private key: no prompt.
          return try enclaveCall {
            switch key.kind {
            case .signing:
              let privateKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: handle)
              return SecureEnclavePublicKey(
                x963Representation: privateKey.publicKey.x963Representation
              )
            case .keyAgreement:
              let privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: handle
              )
              return SecureEnclavePublicKey(
                x963Representation: privateKey.publicKey.x963Representation
              )
            }
          }
        },
        deleteKey: { key in
          try await store.delete(key: key.account)
        },
        sign: { data, key, context in
          guard key.kind == .signing else { throw KeychainError.invalidKey }
          let handle = try await store.load(key: key.account, context: nil)
          return try enclaveCall {
            let privateKey = try SecureEnclave.P256.Signing.PrivateKey(handle, context)
            return try privateKey.signature(for: data).derRepresentation
          }
        },
        sharedSecret: { publicKey, key, context in
          guard key.kind == .keyAgreement else { throw KeychainError.invalidKey }
          let peer: P256.KeyAgreement.PublicKey
          do {
            peer = try P256.KeyAgreement.PublicKey(x963Representation: publicKey.x963Representation)
          } catch {
            throw KeychainError.invalidKey
          }
          let handle = try await store.load(key: key.account, context: nil)
          return try enclaveCall {
            let privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(handle, context)
            let secret = try privateKey.sharedSecretFromKeyAgreement(with: peer)
            return Secret(secret.withUnsafeBytes { Data($0) })
          }
        }
      )
    }
  }

  extension SecureEnclaveKeyDescriptor {
    /// The keychain account of the key's handle. The purpose is part of it, so a signing key
    /// and a key-agreement key may share a tag.
    fileprivate var account: String { "\(kind.rawValue).\(tag)" }
  }

  extension SecureEnclave.P256.Signing.PrivateKey {
    fileprivate init(_ handle: Data, _ context: AuthContext?) throws {
      #if canImport(LocalAuthentication)
        try self.init(dataRepresentation: handle, authenticationContext: context?.context)
      #else
        try self.init(dataRepresentation: handle)
      #endif
    }
  }

  extension SecureEnclave.P256.KeyAgreement.PrivateKey {
    fileprivate init(_ handle: Data, _ context: AuthContext?) throws {
      #if canImport(LocalAuthentication)
        try self.init(dataRepresentation: handle, authenticationContext: context?.context)
      #else
        try self.init(dataRepresentation: handle)
      #endif
    }
  }

  /// Runs a CryptoKit Secure Enclave call and maps its errors to `KeychainError`.
  private func enclaveCall<T>(_ body: () throws -> T) throws -> T {
    do {
      return try body()
    } catch let error as KeychainError {
      throw error
    } catch CryptoKitError.incorrectKeySize, CryptoKitError.incorrectParameterSize {
      throw KeychainError.invalidKey
    } catch {
      let nsError = error as NSError
      if nsError.domain == "com.apple.LocalAuthentication" {  // LAErrorDomain
        throw KeychainError.authenticationFailed
      }
      if nsError.domain == NSOSStatusErrorDomain,
        [errSecAuthFailed, errSecUserCanceled, errSecInteractionNotAllowed].contains(
          OSStatus(nsError.code)
        )
      {
        throw KeychainError.authenticationFailed
      }
      throw KeychainError.cryptoOperationFailed
    }
  }
#endif
