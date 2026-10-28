import Dependencies
import DependenciesMacros
import Foundation

/// Reads and writes generic-password keychain items.
///
/// The closures are the raw, byte-level interface that implementations provide
/// (`KeychainLive`'s `.live(…)`, `.inMemory(…)`, or one written inline in a test). App code
/// uses the typed methods in `KeychainClient+Typed.swift`, addressed by `KeychainKey`.
///
/// `@DependencyClient` generates the memberwise initializer, labelled methods for each
/// closure, and an "unimplemented" default for each endpoint: a test that reaches an endpoint
/// it didn't override fails, and says which one.
@DependencyClient
public struct KeychainClient: Sendable {
  /// Saves `data` under `key`, replacing any existing item (upsert).
  public var save:
    @Sendable (
      _ data: Secret<Data>,
      _ key: String,
      _ accessibility: KeychainAccessibility,
      _ authentication: KeychainAuthentication
    ) async throws -> Void

  /// Loads the bytes under `key`. Throws `KeychainError.itemNotFound` when there is none.
  /// Pass an evaluated `AuthContext` to read a protected item without another prompt.
  public var load: @Sendable (_ key: String, _ context: AuthContext?) async throws -> Secret<Data>

  /// Deletes the item under `key`. Deleting a missing item succeeds (D-3).
  public var delete: @Sendable (_ key: String) async throws -> Void

  /// Deletes every item of this client's service (and access group), and nothing else.
  public var deleteAll: @Sendable () async throws -> Void

  /// Whether an item exists under `key`. Never prompts for authentication and never throws.
  public var exists: @Sendable (_ key: String) async -> Bool = { _ in false }

  /// The keys of every item of this client's service, sorted. Never prompts.
  public var keys: @Sendable () async throws -> [String]

  /// The value under `key` now, then again after each change made through this client.
  /// `nil` means absent. See `stream(for:)` for the details.
  public var stream: @Sendable (_ key: String) -> AsyncStream<Secret<Data>?> = { _ in
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
