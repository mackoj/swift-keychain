import Foundation

// The public API: typed keys in, `Secret` values out. The byte-level closures are `package` (D-12).

extension KeychainClient {
  /// Encodes `secret` with the key's `encode` and saves it with the key's protection.
  public func save<Value>(_ secret: Secret<Value>, for key: KeychainKey<Value>) async throws {
    // exposeSecret: encoding to bytes for storage.
    let data = try key.encode(secret.exposeSecret())
    try await save(Secret(data), key.rawValue, key.accessibility, key.authentication)
  }

  /// Loads and decodes the value under `key`.
  /// - Throws: `KeychainError.itemNotFound`, `.authenticationFailed`, `.decodingFailed`, `.loadFailed`.
  public func load<Value>(
    for key: KeychainKey<Value>,
    context: AuthContext? = nil
  ) async throws -> Secret<Value> {
    try await load(key.rawValue, context).map(key.decode)
  }

  /// Like `load(for:context:)`, but returns `nil` when there is no item.
  public func loadIfPresent<Value>(
    for key: KeychainKey<Value>,
    context: AuthContext? = nil
  ) async throws -> Secret<Value>? {
    do {
      return try await load(for: key, context: context)
    } catch KeychainError.itemNotFound {
      return nil
    }
  }

  /// Deletes the item under `key`. Succeeds when there is none.
  public func delete<Value>(for key: KeychainKey<Value>) async throws {
    try await delete(key.rawValue)
  }

  /// Moves the item under `key` to `newKey`, keeping its bytes and protection, without a prompt.
  /// An item already under `newKey` is replaced (D-11).
  /// - Throws: `KeychainError.itemNotFound` when there is no item under `key`.
  public func rename<Value>(_ key: KeychainKey<Value>, to newKey: KeychainKey<Value>) async throws {
    try await rename(key.rawValue, newKey.rawValue)
  }

  /// Whether an item exists under `key`. Never prompts.
  public func exists<Value>(for key: KeychainKey<Value>) async -> Bool {
    await exists(key.rawValue)
  }

  /// The typed keys of this client's items, in account order. `key` turns an account into its
  /// key, or returns `nil` to skip it. Never prompts.
  ///
  /// ```swift
  /// let tokens = try await keychain.keys { account in
  ///   account.hasPrefix("token.") ? KeychainKey<String>(account) : nil
  /// }
  /// ```
  public func keys<Value>(
    _ key: (_ account: String) throws -> KeychainKey<Value>?
  ) async throws -> [KeychainKey<Value>] {
    try await keys().compactMap(key)
  }

  /// The value under `key` now, then again after each change made through this client.
  ///
  /// - Yields `nil` when the item is absent or deleted, or when its bytes don't decode.
  /// - The first element is the current value, read without a prompt. For an item behind an
  ///   authentication gate that read is not possible, so the stream starts with the next change.
  /// - Changes made by another process (an app extension, another client instance) are not
  ///   observed: the keychain has no public change notification (D-4).
  ///
  /// Cancel the consuming task to stop.
  public func stream<Value>(for key: KeychainKey<Value>) -> AsyncStream<Secret<Value>?> {
    let raw = stream(key.rawValue)
    return AsyncStream { continuation in
      let task = Task {
        for await data in raw {
          continuation.yield(try? data?.map(key.decode))
        }
        continuation.finish()
      }
      continuation.onTermination = { _ in task.cancel() }
    }
  }
}
