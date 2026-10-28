import Foundation

/// What a Secure Enclave key is for. A key has one purpose; the type parameter of
/// `SecureEnclaveKey` makes the compiler check it.
public protocol SecureEnclaveKeyPurpose: Sendable {
  static var kind: SecureEnclaveKeyKind { get }
}

/// P-256 ECDSA signing (SHA-256 digests).
public enum Signing: SecureEnclaveKeyPurpose {
  public static var kind: SecureEnclaveKeyKind { .signing }
}

/// P-256 ECDH key agreement.
public enum KeyAgreement: SecureEnclaveKeyPurpose {
  public static var kind: SecureEnclaveKeyKind { .keyAgreement }
}

/// The runtime form of a key's purpose.
public enum SecureEnclaveKeyKind: String, Sendable, Hashable {
  case signing
  case keyAgreement
}

/// When a Secure Enclave key can be used. Only device-only classes exist: a Secure Enclave key
/// can never leave the device it was made on.
public enum SecureEnclaveAccessibility: Sendable, Hashable, CaseIterable {
  case afterFirstUnlockThisDeviceOnly
  case whenUnlockedThisDeviceOnly
  case whenPasscodeSetThisDeviceOnly

  /// The equivalent keychain accessibility.
  public var keychainAccessibility: KeychainAccessibility {
    switch self {
    case .afterFirstUnlockThisDeviceOnly: .afterFirstUnlockThisDeviceOnly
    case .whenUnlockedThisDeviceOnly: .whenUnlockedThisDeviceOnly
    case .whenPasscodeSetThisDeviceOnly: .whenPasscodeSetThisDeviceOnly
    }
  }
}

/// A typed address for a P-256 private key that lives in the Secure Enclave.
///
/// The private key never leaves the enclave. What the keychain stores, under `tag`, is an
/// encrypted handle that only this device's enclave can use.
///
/// ```swift
/// extension SecureEnclaveKey<Signing> {
///   static let deviceIdentity = SecureEnclaveKey("device.identity", authentication: .biometricOrPasscode)
/// }
/// ```
public struct SecureEnclaveKey<Purpose: SecureEnclaveKeyPurpose>: Sendable, Hashable {
  public let tag: String
  public let accessibility: SecureEnclaveAccessibility
  /// The gate on each use of the private key (signing, key agreement), enforced by the enclave.
  public let authentication: KeychainAuthentication

  public init(
    _ tag: String,
    accessibility: SecureEnclaveAccessibility = .afterFirstUnlockThisDeviceOnly,
    authentication: KeychainAuthentication = .none
  ) {
    self.tag = tag
    self.accessibility = accessibility
    self.authentication = authentication
  }

  /// The untyped form passed to `SecureEnclaveClient`'s closures.
  public var descriptor: SecureEnclaveKeyDescriptor {
    SecureEnclaveKeyDescriptor(
      tag: tag,
      kind: Purpose.kind,
      accessibility: accessibility,
      authentication: authentication
    )
  }
}

/// A Secure Enclave key without its purpose type: what implementations receive.
public struct SecureEnclaveKeyDescriptor: Sendable, Hashable {
  public let tag: String
  public let kind: SecureEnclaveKeyKind
  public let accessibility: SecureEnclaveAccessibility
  public let authentication: KeychainAuthentication

  public init(
    tag: String,
    kind: SecureEnclaveKeyKind,
    accessibility: SecureEnclaveAccessibility,
    authentication: KeychainAuthentication
  ) {
    self.tag = tag
    self.kind = kind
    self.accessibility = accessibility
    self.authentication = authentication
  }
}

/// The public half of a P-256 key, in ANSI X9.63 form (`04 ‖ X ‖ Y`, 65 bytes).
///
/// Public keys are not secret; this type is safe to log, store and send.
public struct SecureEnclavePublicKey: Sendable, Hashable, Codable {
  public let x963Representation: Data

  public init(x963Representation: Data) {
    self.x963Representation = x963Representation
  }
}
