#if canImport(Security)
  import Dependencies
  import Foundation
  import Keychain

  extension KeychainClient: DependencyKey {
    /// The real keychain, scoped to the main bundle identifier.
    public static let liveValue = KeychainClient.live(
      service: Bundle.main.bundleIdentifier ?? "swift-keychain"
    )

    /// A client for the real keychain.
    ///
    /// - Parameters:
    ///   - service: The `kSecAttrService` of every item. `deleteAll` and `keys` see only this
    ///     service's items.
    ///   - accessGroup: A `kSecAttrAccessGroup` shared with app extensions or other apps.
    ///   - dataProtection: On macOS, uses the data protection keychain (the iOS one), which
    ///     needs the `keychain-access-groups` entitlement. Pass `false` for unsigned binaries such
    ///     as `swift test`. Ignored on other platforms.
    public static func live(
      service: String,
      accessGroup: String? = nil,
      dataProtection: Bool = true
    ) -> KeychainClient {
      let store = KeychainStore(
        service: service,
        accessGroup: accessGroup,
        dataProtection: dataProtection
      )
      return KeychainClient(
        save: { secret, key, accessibility, authentication in
          // exposeSecret: SecItemAdd takes the bytes.
          try await store.save(
            secret.exposeSecret(),
            key: key,
            accessibility: accessibility,
            authentication: authentication
          )
        },
        load: { key, context in Secret(try await store.load(key: key, context: context)) },
        delete: { key in try await store.delete(key: key) },
        deleteAll: { try await store.deleteAll() },
        exists: { key in await store.exists(key: key) },
        keys: { try await store.keys() },
        stream: { key in store.stream(key: key) }
      )
    }
  }
#endif
