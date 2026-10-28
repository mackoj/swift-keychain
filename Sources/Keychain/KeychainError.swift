import Foundation

#if !canImport(Darwin)
  // Darwin's `OSStatus`, so this module builds on Linux.
  public typealias OSStatus = Int32
#endif

/// Errors from keychain and Secure Enclave operations.
///
/// Invariant: no case carries secret bytes. Only keys, `OSStatus` codes and fixed messages,
/// so an error can be logged as is.
public enum KeychainError: Error, Sendable, Equatable {
  /// No item or key exists for the key.
  case itemNotFound
  /// The key's `encode` closure failed.
  case encodingFailed
  /// The stored bytes could not be decoded into the key's value type.
  case decodingFailed
  /// The user cancelled or failed authentication, or the item needs a prompt that isn't
  /// allowed here (no UI, device locked).
  case authenticationFailed
  /// The process lacks the `keychain-access-groups` entitlement the data protection keychain
  /// needs (`errSecMissingEntitlement`). Sign the binary, or use `dataProtection: false` on macOS.
  case missingEntitlement
  /// This device has no Secure Enclave (the simulator, older Macs, Linux).
  case secureEnclaveUnavailable
  /// The stored key, or a peer's public key, is malformed or of another purpose.
  case invalidKey
  /// A Secure Enclave or CryptoKit operation failed for a reason other than authentication.
  case cryptoOperationFailed
  case saveFailed(OSStatus)
  case loadFailed(OSStatus)
  case deleteFailed(OSStatus)
}

extension KeychainError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .itemNotFound: "The keychain item was not found."
    case .encodingFailed: "The value could not be encoded for the keychain."
    case .decodingFailed: "The keychain value could not be decoded."
    case .authenticationFailed:
      "Authentication failed, was cancelled, or is not possible right now."
    case .missingEntitlement: "The process is missing the keychain-access-groups entitlement."
    case .secureEnclaveUnavailable: "This device has no Secure Enclave."
    case .invalidKey: "The key is malformed or has another purpose."
    case .cryptoOperationFailed: "The cryptographic operation failed."
    case .saveFailed(let status): "Keychain save failed (OSStatus \(status))."
    case .loadFailed(let status): "Keychain load failed (OSStatus \(status))."
    case .deleteFailed(let status): "Keychain delete failed (OSStatus \(status))."
    }
  }
}
