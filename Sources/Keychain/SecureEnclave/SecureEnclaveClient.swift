import Dependencies
import DependenciesMacros
import Foundation

/// Creates and uses P-256 keys held in the Secure Enclave.
///
/// As with `KeychainClient`, the closures are the untyped interface implementations provide;
/// app code calls the typed methods below, which take a `SecureEnclaveKey<Signing>` or
/// `SecureEnclaveKey<KeyAgreement>`.
@DependencyClient
public struct SecureEnclaveClient: Sendable {
  /// Whether this device has a Secure Enclave.
  public var isAvailable: @Sendable () -> Bool = { false }

  /// Creates a new private key under the key's tag, replacing any key already there, and
  /// returns its public key.
  public var createKey:
    @Sendable (_ key: SecureEnclaveKeyDescriptor) async throws -> SecureEnclavePublicKey

  /// The public key of the private key under the key's tag. Never prompts.
  /// Throws `KeychainError.itemNotFound` when there is none.
  public var publicKey:
    @Sendable (_ key: SecureEnclaveKeyDescriptor) async throws -> SecureEnclavePublicKey

  /// Deletes the private key under the key's tag. Deleting a missing key succeeds.
  public var deleteKey: @Sendable (_ key: SecureEnclaveKeyDescriptor) async throws -> Void

  /// Signs the SHA-256 digest of `data`. Returns a DER-encoded ECDSA signature.
  public var sign:
    @Sendable (
      _ data: Data,
      _ key: SecureEnclaveKeyDescriptor,
      _ context: AuthContext?
    ) async throws -> Data

  /// The raw ECDH shared secret between the private key and `publicKey`.
  /// Derive a symmetric key from it (HKDF) before using it.
  public var sharedSecret:
    @Sendable (
      _ publicKey: SecureEnclavePublicKey,
      _ key: SecureEnclaveKeyDescriptor,
      _ context: AuthContext?
    ) async throws -> Secret<Data>
}

// MARK: - Typed API

extension SecureEnclaveClient {
  /// Creates a new private key, replacing any key with the same tag, and returns its public key.
  public func createKey<Purpose>(
    _ key: SecureEnclaveKey<Purpose>
  ) async throws -> SecureEnclavePublicKey {
    try await createKey(key.descriptor)
  }

  /// The public key for `key`. Throws `KeychainError.itemNotFound` when there is none.
  public func publicKey<Purpose>(
    for key: SecureEnclaveKey<Purpose>
  ) async throws -> SecureEnclavePublicKey {
    try await publicKey(key.descriptor)
  }

  /// The public key for `key`, creating the private key first if there is none.
  public func publicKeyCreatingIfNeeded<Purpose>(
    for key: SecureEnclaveKey<Purpose>
  ) async throws -> SecureEnclavePublicKey {
    do {
      return try await publicKey(key.descriptor)
    } catch KeychainError.itemNotFound {
      return try await createKey(key.descriptor)
    }
  }

  /// Deletes the private key for `key`. Succeeds when there is none.
  public func deleteKey<Purpose>(_ key: SecureEnclaveKey<Purpose>) async throws {
    try await deleteKey(key.descriptor)
  }

  /// Signs the SHA-256 digest of `data`. Returns a DER-encoded ECDSA signature.
  public func sign(
    _ data: Data,
    with key: SecureEnclaveKey<Signing>,
    context: AuthContext? = nil
  ) async throws -> Data {
    try await sign(data, key.descriptor, context)
  }

  /// The raw ECDH shared secret between `key` and `publicKey`.
  public func sharedSecret(
    with publicKey: SecureEnclavePublicKey,
    using key: SecureEnclaveKey<KeyAgreement>,
    context: AuthContext? = nil
  ) async throws -> Secret<Data> {
    try await sharedSecret(publicKey, key.descriptor, context)
  }
}

// MARK: - Dependency

extension SecureEnclaveClient: TestDependencyKey {
  /// Every endpoint unimplemented; `isAvailable` returns `false`.
  public static let testValue = SecureEnclaveClient()
}

extension DependencyValues {
  /// The Secure Enclave. The live value comes from `KeychainLive` when the app links it.
  public var secureEnclave: SecureEnclaveClient {
    get { self[SecureEnclaveClient.self] }
    set { self[SecureEnclaveClient.self] = newValue }
  }
}
