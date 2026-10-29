import Dependencies
import DependenciesMacros
import Foundation

/// Reads and writes generic-password keychain items.
///
/// Call it through the typed methods in `KeychainClient+Typed.swift`, addressed by
/// `KeychainKey`. The string-keyed closures below are the byte-level interface the package's own
/// implementations fill in (`KeychainLive`'s `.live(…)`, `.inMemory(…)`, `.noop`, `.failing(_:)`);
/// they and the memberwise initializer are `package`, so code outside this package never spells
/// a raw account string (D-12). `deleteAll` and `keys` take no key, so they stay callable.
///
/// `@DependencyClient` generates the memberwise initializer and an "unimplemented" default for
/// each endpoint: a test that reaches an endpoint it didn't expect fails, and says which one.
@DependencyClient
public struct KeychainClient: Sendable {
  /// Saves `data` under `key`, replacing any existing item (upsert).
  package var save:
    @Sendable (
      _ data: Secret<Data>,
      _ key: String,
      _ accessibility: KeychainAccessibility,
      _ authentication: KeychainAuthentication
    ) async throws -> Void

  /// Loads the bytes under `key`. Throws `KeychainError.itemNotFound` when there is none.
  /// Pass an evaluated `AuthContext` to read a protected item without another prompt.
  package var load: @Sendable (_ key: String, _ context: AuthContext?) async throws -> Secret<Data>

  /// Deletes the item under `key`. Deleting a missing item succeeds (D-3).
  package var delete: @Sendable (_ key: String) async throws -> Void

  /// Moves the item under `key` to `newKey` without reading its bytes, so it never prompts,
  /// even for a gated item. The item keeps its protection. An item already under `newKey` is
  /// replaced. Throws `KeychainError.itemNotFound` when there is no item under `key` (D-11).
  package var rename: @Sendable (_ key: String, _ newKey: String) async throws -> Void

  /// Deletes every item of this client's service (and access group), and nothing else.
  public package(set) var deleteAll: @Sendable () async throws -> Void

  /// Whether an item exists under `key`. Never prompts for authentication and never throws.
  package var exists: @Sendable (_ key: String) async -> Bool = { _ in false }

  /// The account (`KeychainKey.rawValue`) of every item of this client's service, sorted.
  /// Never prompts. `keys(_:)` turns them into typed keys.
  public package(set) var keys: @Sendable () async throws -> [String]

  /// The value under `key` now, then again after each change made through this client.
  /// `nil` means absent. See `stream(for:)` for the details.
  package var stream: @Sendable (_ key: String) -> AsyncStream<Secret<Data>?> = { _ in
    AsyncStream { $0.finish() }
  }
}

extension KeychainClient: TestDependencyKey {
  /// Every endpoint unimplemented: an unexpected keychain call fails the test by name.
  public static let testValue = KeychainClient()

  /// A fresh in-memory keychain, so previews never touch the real one.
  public static var previewValue: KeychainClient { .inMemory() }
}

extension DependencyValues {
  /// The keychain. The live value comes from `KeychainLive` when the app links it.
  ///
  /// ```swift
  /// @Dependency(\.keychain) var keychain
  /// ```
  public var keychain: KeychainClient {
    get { self[KeychainClient.self] }
    set { self[KeychainClient.self] = newValue }
  }
}
