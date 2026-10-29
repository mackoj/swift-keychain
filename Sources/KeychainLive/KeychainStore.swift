#if canImport(Security)
  import Foundation
  import Keychain
  import Security

  #if canImport(LocalAuthentication)
    import LocalAuthentication
  #endif

  /// Serializes every `SecItem*` call for one service (and access group).
  ///
  /// Internal to `KeychainLive`: callers go through `KeychainClient` and `SecureEnclaveClient`.
  actor KeychainStore {
    private let service: String
    private let accessGroup: String?
    private let dataProtection: Bool
    private var subscribers = KeychainSubscribers()

    /// - Parameter dataProtection: Adds `kSecUseDataProtectionKeychain` on macOS (D-2).
    init(service: String, accessGroup: String?, dataProtection: Bool) {
      self.service = service
      self.accessGroup = accessGroup
      self.dataProtection = dataProtection
    }

    // MARK: Save

    func save(
      _ data: Data,
      key: String,
      accessibility: KeychainAccessibility,
      authentication: KeychainAuthentication
    ) throws {
      var protection: [CFString: Any] = [:]
      if authentication == .none {
        protection[kSecAttrAccessible] = accessibility.cfValue
      } else {
        // kSecAttrAccessControl replaces kSecAttrAccessible; it carries both.
        protection[kSecAttrAccessControl] = try accessControl(accessibility, authentication)
      }

      var add = baseQuery(key: key).merging(protection) { $1 }
      add[kSecValueData] = data
      var status = SecItemAdd(add as CFDictionary, nil)

      if status == errSecDuplicateItem {
        if authentication == .none {
          // Update in place: atomic, and the existing item is ungated so no prompt.
          var attributes = protection
          attributes[kSecValueData] = data
          // If the existing item is gated, fail instead of prompting, and replace it below.
          let match = Self.withoutPrompt(baseQuery(key: key))
          status = SecItemUpdate(match as CFDictionary, attributes as CFDictionary)
        } else {
          status = errSecItemNotFound
        }
        // A gated item can't be updated without a prompt, and another process may have
        // deleted the item since the add: replace it (D-5).
        if status == errSecItemNotFound || status == errSecInteractionNotAllowed
          || status == errSecAuthFailed
        {
          SecItemDelete(baseQuery(key: key) as CFDictionary)
          status = SecItemAdd(add as CFDictionary, nil)
        }
      }

      guard status == errSecSuccess else { throw error(status, else: .saveFailed(status)) }
      // A gated item is never sent to streams: a stream must not reveal what a read would gate.
      subscribers.yield(authentication == .none ? Secret(data) : nil, for: key)
    }

    // MARK: Load

    func load(key: String, context: AuthContext?) throws -> Data {
      var query = baseQuery(key: key)
      query[kSecReturnData] = true
      query[kSecMatchLimit] = kSecMatchLimitOne
      #if canImport(LocalAuthentication)
        if let context { query[kSecUseAuthenticationContext] = context.context }
      #endif
      return try copyData(query)
    }

    /// Reads without ever showing a prompt. `nil` when absent; throws when gated.
    private func loadWithoutPrompt(key: String) throws -> Data? {
      var query = baseQuery(key: key)
      query[kSecReturnData] = true
      query[kSecMatchLimit] = kSecMatchLimitOne
      do {
        return try copyData(Self.withoutPrompt(query))
      } catch KeychainError.itemNotFound {
        return nil
      }
    }

    private func copyData(_ query: [CFString: Any]) throws -> Data {
      var result: AnyObject?
      let status = SecItemCopyMatching(query as CFDictionary, &result)
      guard status == errSecSuccess else { throw error(status, else: .loadFailed(status)) }
      guard let data = result as? Data else { throw KeychainError.decodingFailed }
      return data
    }

    // MARK: Delete

    func delete(key: String) throws {
      let status = SecItemDelete(baseQuery(key: key) as CFDictionary)
      switch status {
      case errSecSuccess:
        subscribers.yield(nil, for: key)
      case errSecItemNotFound:
        return  // Idempotent (D-3).
      default:
        throw error(status, else: .deleteFailed(status))
      }
    }

    // MARK: Rename

    /// Changes the item's account attribute: its bytes are never read, so no prompt (D-11).
    func rename(key: String, to newKey: String) throws {
      guard exists(key: key) else { throw KeychainError.itemNotFound }
      guard key != newKey else { return }
      let replaced = SecItemDelete(baseQuery(key: newKey) as CFDictionary)
      guard replaced == errSecSuccess || replaced == errSecItemNotFound else {
        throw error(replaced, else: .deleteFailed(replaced))
      }
      let match = Self.withoutPrompt(baseQuery(key: key))
      let changes = [kSecAttrAccount: newKey] as CFDictionary
      let status = SecItemUpdate(match as CFDictionary, changes)
      guard status == errSecSuccess else { throw error(status, else: .saveFailed(status)) }
      subscribers.yield(nil, for: key)
      // Like a save: a gated item is never sent to streams, and this read never prompts.
      subscribers.yield((try? loadWithoutPrompt(key: newKey))?.map { Secret($0) }, for: newKey)
    }

    func deleteAll() throws {
      let query = serviceQuery()
      // The file-based macOS keychain deletes one match per call; loop until none is left.
      var status: OSStatus
      repeat {
        status = SecItemDelete(query as CFDictionary)
      } while status == errSecSuccess
      guard status == errSecItemNotFound else { throw error(status, else: .deleteFailed(status)) }
      subscribers.yieldNilToAll()
    }

    // MARK: Exists, keys

    func exists(key: String) -> Bool {
      var query = baseQuery(key: key)
      query[kSecReturnAttributes] = true
      query[kSecMatchLimit] = kSecMatchLimitOne
      let status = SecItemCopyMatching(Self.withoutPrompt(query) as CFDictionary, nil)
      // A gated item answers "interaction not allowed": it exists.
      return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    func keys() throws -> [String] {
      var query = serviceQuery()
      query[kSecReturnAttributes] = true
      query[kSecMatchLimit] = kSecMatchLimitAll
      var result: AnyObject?
      let status = SecItemCopyMatching(Self.withoutPrompt(query) as CFDictionary, &result)
      if status == errSecItemNotFound { return [] }
      guard status == errSecSuccess else { throw error(status, else: .loadFailed(status)) }
      let items = result as? [[CFString: Any]] ?? []
      return items.compactMap { $0[kSecAttrAccount] as? String }.sorted()
    }

    // MARK: Stream

    nonisolated func stream(key: String) -> AsyncStream<Secret<Data>?> {
      AsyncStream { continuation in
        Task { await self.subscribe(continuation, key: key) }
      }
    }

    private func subscribe(_ continuation: AsyncStream<Secret<Data>?>.Continuation, key: String) {
      // Registering and reading the first value in one actor turn: no change can fall between.
      let id = subscribers.add(continuation, for: key)
      continuation.onTermination = { _ in Task { await self.unsubscribe(id, key: key) } }
      do {
        let data: Data? = try loadWithoutPrompt(key: key)
        continuation.yield(data.map { Secret($0) })
      } catch {
        // A gated item (or a read error) yields nothing first: a stream never prompts (D-4).
      }
    }

    private func unsubscribe(_ id: UUID, key: String) {
      subscribers.remove(id, for: key)
    }

    // MARK: Queries

    private func serviceQuery() -> [CFString: Any] {
      var query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: service,
      ]
      if let accessGroup { query[kSecAttrAccessGroup] = accessGroup }
      #if os(macOS)
        if dataProtection { query[kSecUseDataProtectionKeychain] = true }
      #endif
      return query
    }

    private func baseQuery(key: String) -> [CFString: Any] {
      var query = serviceQuery()
      query[kSecAttrAccount] = key
      return query
    }

    /// `query` set to fail with `errSecInteractionNotAllowed` instead of prompting.
    /// (tvOS has no LocalAuthentication, and no prompts to suppress.)
    private static func withoutPrompt(_ query: [CFString: Any]) -> [CFString: Any] {
      #if canImport(LocalAuthentication)
        var query = query
        let context = LAContext()
        context.interactionNotAllowed = true
        query[kSecUseAuthenticationContext] = context
        return query
      #else
        return query
      #endif
    }

    private func error(_ status: OSStatus, else fallback: KeychainError) -> KeychainError {
      switch status {
      case errSecItemNotFound: .itemNotFound
      case errSecMissingEntitlement: .missingEntitlement
      case errSecAuthFailed, errSecUserCanceled, errSecInteractionNotAllowed: .authenticationFailed
      default: fallback
      }
    }
  }

  // MARK: - Security mappings

  extension KeychainAccessibility {
    var cfValue: CFString {
      switch self {
      case .afterFirstUnlock: kSecAttrAccessibleAfterFirstUnlock
      case .afterFirstUnlockThisDeviceOnly: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
      case .whenUnlocked: kSecAttrAccessibleWhenUnlocked
      case .whenUnlockedThisDeviceOnly: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
      case .whenPasscodeSetThisDeviceOnly: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
      }
    }
  }

  extension KeychainAuthentication {
    var flags: SecAccessControlCreateFlags {
      switch self {
      case .none: []
      case .biometric: .biometryAny
      case .biometricCurrentSet: .biometryCurrentSet
      case .biometricOrPasscode: .userPresence
      case .devicePasscode: .devicePasscode
      }
    }
  }

  /// A `SecAccessControl` for the accessibility and gate, plus `extraFlags`
  /// (`.privateKeyUsage` for Secure Enclave keys).
  func accessControl(
    _ accessibility: KeychainAccessibility,
    _ authentication: KeychainAuthentication,
    extraFlags: SecAccessControlCreateFlags = []
  ) throws -> SecAccessControl {
    var error: Unmanaged<CFError>?
    guard
      let control = SecAccessControlCreateWithFlags(
        nil,
        accessibility.cfValue,
        authentication.flags.union(extraFlags),
        &error
      )
    else {
      let status = error.map { OSStatus(CFErrorGetCode($0.takeRetainedValue())) } ?? errSecParam
      throw KeychainError.saveFailed(status)
    }
    return control
  }
#endif
