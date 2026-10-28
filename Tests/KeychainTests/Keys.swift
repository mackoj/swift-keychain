import Foundation
import Keychain

struct Credentials: Codable, Equatable, Sendable {
  var username: String
  var pin: String
}

extension KeychainKey where Value == String {
  static let authToken = KeychainKey("auth.token")
  static let vaultPassword = KeychainKey("vault.password", authentication: .biometricOrPasscode)
}

extension KeychainKey where Value == Data {
  static let encryptionKey = KeychainKey("crypto.encryption-key")
}

extension KeychainKey where Value == Credentials {
  static let credentials = KeychainKey("user.credentials")
}

extension SecureEnclaveKey<Signing> {
  static let deviceIdentity = SecureEnclaveKey("device.identity")
  static let paymentApproval = SecureEnclaveKey(
    "payment.approval",
    authentication: .biometricCurrentSet
  )
}

extension SecureEnclaveKey<KeyAgreement> {
  static let sessionAgreement = SecureEnclaveKey("session.agreement")
}
