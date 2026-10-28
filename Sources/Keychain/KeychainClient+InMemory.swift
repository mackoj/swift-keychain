import Foundation

/// One prefilled item for `KeychainClient.inMemory(authenticate:prefilling:)`.
public struct KeychainEntry: Sendable {
  let key: String
  let data: Data
  let authentication: KeychainAuthentication

  /// Encodes `secret` with `key`'s serialization and keeps its authentication gate.
  public init<Value>(_ secret: Secret<Value>, for key: KeychainKey<Value>) throws {
    self.key = key.rawValue
    // exposeSecret: encoding to bytes for storage.
    self.data = try key.encode(secret.exposeSecret())
    self.authentication = key.authentication
  }
}

/// Builds the entries of a prefilled in-memory keychain.
@resultBuilder
public enum KeychainPrefill {
  public static func buildExpression(_ entry: KeychainEntry) -> [KeychainEntry] { [entry] }
  public static func buildBlock(_ components: [KeychainEntry]...) -> [KeychainEntry] {
    components.flatMap(\.self)
  }
  public static func buildArray(_ components: [[KeychainEntry]]) -> [KeychainEntry] {
    components.flatMap(\.self)
  }
  public static func buildOptional(_ component: [KeychainEntry]?) -> [KeychainEntry] {
    component ?? []
  }
  public static func buildEither(first component: [KeychainEntry]) -> [KeychainEntry] { component }
  public static func buildEither(second component: [KeychainEntry]) -> [KeychainEntry] { component }
}

/// Decides whether a simulated authentication prompt succeeds. Receives the item's gate and the
/// context passed to the read.
public typealias Authenticator =
  @Sendable (KeychainAuthentication, AuthContext?) async -> Bool

extension KeychainClient {
  /// A client that accepts every call and stores nothing: saves succeed, loads throw
  /// `itemNotFound`, streams yield `nil` once.
  public static let noop = KeychainClient(
    save: { _, _, _, _ in },
    load: { _, _ in throw KeychainError.itemNotFound },
    delete: { _ in },
    deleteAll: {},
    exists: { _ in false },
    keys: { [] },
    stream: { _ in
      AsyncStream { continuation in
        continuation.yield(nil)
        continuation.finish()
      }
    }
  )

  /// A working keychain held in memory. Each call returns an independent store.
  ///
  /// ```swift
  /// let keychain = try KeychainClient.inMemory {
  ///   try KeychainEntry(Secret("t0k3n"), for: .authToken)
  /// }
  /// ```
  ///
  /// - Parameters:
  ///   - authenticate: Simulates the prompt for items saved with an authentication gate.
  ///     The default lets every read through; pass `{ _, _ in false }` to test a refusal.
  ///   - prefilling: The items present from the start.
  public static func inMemory(
    authenticate: @escaping Authenticator = { _, _ in true },
    @KeychainPrefill prefilling entries: () throws -> [KeychainEntry]
  ) rethrows -> KeychainClient {
    inMemory(entries: try entries(), authenticate: authenticate)
  }

  /// An empty in-memory keychain. See `inMemory(authenticate:prefilling:)`.
  public static func inMemory(
    authenticate: @escaping Authenticator = { _, _ in true }
  ) -> KeychainClient {
    inMemory(entries: [], authenticate: authenticate)
  }

  private static func inMemory(
    entries: [KeychainEntry],
    authenticate: @escaping Authenticator
  ) -> KeychainClient {
    let storage = InMemoryKeychain(entries: entries, authenticate: authenticate)
    return KeychainClient(
      save: { secret, key, _, authentication in
        // exposeSecret: the store holds bytes.
        await storage.save(secret.exposeSecret(), key: key, authentication: authentication)
      },
      load: { key, context in try await storage.load(key: key, context: context) },
      delete: { key in await storage.delete(key: key) },
      deleteAll: { await storage.deleteAll() },
      exists: { key in await storage.exists(key: key) },
      keys: { await storage.keys() },
      stream: { key in storage.stream(key: key) }
    )
  }
}

private actor InMemoryKeychain {
  private struct Item {
    var data: Data
    var authentication: KeychainAuthentication
  }

  private var items: [String: Item] = [:]
  private var subscribers = KeychainSubscribers()
  private let authenticate: Authenticator

  init(entries: [KeychainEntry], authenticate: @escaping Authenticator) {
    for entry in entries {
      items[entry.key] = Item(data: entry.data, authentication: entry.authentication)
    }
    self.authenticate = authenticate
  }

  func save(_ data: Data, key: String, authentication: KeychainAuthentication) {
    items[key] = Item(data: data, authentication: authentication)
    subscribers.yield(Secret(data), for: key)
  }

  func load(key: String, context: AuthContext?) async throws -> Secret<Data> {
    guard let item = items[key] else { throw KeychainError.itemNotFound }
    if item.authentication != .none {
      guard await authenticate(item.authentication, context) else {
        throw KeychainError.authenticationFailed
      }
    }
    return Secret(item.data)
  }

  func delete(key: String) {
    guard items.removeValue(forKey: key) != nil else { return }
    subscribers.yield(nil, for: key)
  }

  func deleteAll() {
    items.removeAll()
    subscribers.yieldNilToAll()
  }

  func exists(key: String) -> Bool { items[key] != nil }

  func keys() -> [String] { items.keys.sorted() }

  nonisolated func stream(key: String) -> AsyncStream<Secret<Data>?> {
    AsyncStream { continuation in
      Task { await self.subscribe(continuation, key: key) }
    }
  }

  private func subscribe(_ continuation: AsyncStream<Secret<Data>?>.Continuation, key: String) {
    // Registering and reading the first value in one actor turn: no change can fall between.
    let id = subscribers.add(continuation, for: key)
    continuation.onTermination = { _ in Task { await self.unsubscribe(id, key: key) } }
    switch items[key] {
    case nil: continuation.yield(nil)
    case let item? where item.authentication == .none: continuation.yield(Secret(item.data))
    case .some: break  // Behind a gate: a stream never prompts (D-4).
    }
  }

  private func unsubscribe(_ id: UUID, key: String) {
    subscribers.remove(id, for: key)
  }
}
