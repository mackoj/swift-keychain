/// When a keychain item can be read. Maps to the `kSecAttrAccessible*` constants.
///
/// The mapping to `CFString` lives in `KeychainLive`, so this module never imports Security.
public enum KeychainAccessibility: Sendable, Hashable, CaseIterable {
  /// After the first unlock since boot; migrates to new devices through backups.
  case afterFirstUnlock
  /// After the first unlock since boot; never leaves this device.
  case afterFirstUnlockThisDeviceOnly
  /// While the device is unlocked; migrates to new devices through backups.
  case whenUnlocked
  /// While the device is unlocked; never leaves this device.
  case whenUnlockedThisDeviceOnly
  /// While the device is unlocked and has a passcode; deleted if the passcode is removed.
  case whenPasscodeSetThisDeviceOnly

  /// Whether items with this accessibility stay on this device.
  public var isThisDeviceOnly: Bool {
    switch self {
    case .afterFirstUnlock, .whenUnlocked: false
    case .afterFirstUnlockThisDeviceOnly, .whenUnlockedThisDeviceOnly,
      .whenPasscodeSetThisDeviceOnly:
      true
    }
  }
}

/// The user-authentication gate on an item or a Secure Enclave key.
/// Maps to `SecAccessControlCreateFlags`.
public enum KeychainAuthentication: Sendable, Hashable, CaseIterable {
  /// No gate (default).
  case none
  /// Face ID, Touch ID or Optic ID, any enrolled biometry. No passcode fallback.
  case biometric
  /// Like `biometric`, but the item becomes unreadable when biometry enrollment changes
  /// (a finger or face is added or removed).
  case biometricCurrentSet
  /// Biometry, with the device passcode as fallback.
  case biometricOrPasscode
  /// The device passcode only.
  case devicePasscode
}
