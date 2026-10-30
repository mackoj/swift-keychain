import Foundation

/// One prefilled item for `KeychainClient.inMemory(authenticate:prefilling:)`.
public struct KeychainEntry: Sendable {
  let key: String
  let data: Data
  let authentication: KeychainAuthentication
  let attributes: KeychainItemAttributes

  /// Encodes `secret` with `key`'s serialization and keeps its authentication gate.
  public init<Value>(
    _ secret: Secret<Value>,
    for key: KeychainKey<Value>,
    attributes: KeychainItemAttributes = .init()
  ) throws {
    self.key = key.rawValue
    // exposeSecret: encoding to bytes for storage.
    self.data = try key.encode(secret.exposeSecret())
    self.authentication = key.authentication
    self.attributes = attributes.normalized
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
  /// `itemNotFound`, attributes are `nil`, streams yield `nil` once.
  public static let noop = KeychainClient(
    save: { _, _, _, _, _ in },
    load: { _, _ in throw KeychainError.itemNotFound },
    delete: { _ in },
    rename: { _, _ in throw KeychainError.itemNotFound },
    attributes: { _ in nil },
    updateAttributes: { _, _ in throw KeychainError.itemNotFound },
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

  /// A client whose every throwing call throws `error`: a keychain that refuses access, such as
  /// one missing its entitlement. `exists` is `false`; streams finish without a value.
  ///
  /// ```swift
  /// let keychain = KeychainClient.failing(.missingEntitlement)
  /// ```
  public static func failing(_ error: KeychainError) -> KeychainClient {
    KeychainClient(
      save: { _, _, _, _, _ in throw error },
      load: { _, _ in throw error },
      delete: { _ in throw error },
      rename: { _, _ in throw error },
      attributes: { _ in throw error },
      updateAttributes: { _, _ in throw error },
      deleteAll: { throw error },
      exists: { _ in false },
      keys: { throw error },
      stream: { _ in AsyncStream { $0.finish() } }
    )
  }

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
      save: { secret, key, _, authentication, attributes in
        // exposeSecret: the store holds bytes.
        await storage.save(
          secret.exposeSecret(),
          key: key,
          authentication: authentication,
          attributes: attributes
        )
      },
      load: { key, context in try await storage.load(key: key, context: context) },
      delete: { key in await storage.delete(key: key) },
      rename: { key, newKey in try await storage.rename(key: key, to: newKey) },
      attributes: { key in await storage.attributes(key: key) },
      updateAttributes: { key, attributes in
        try await storage.updateAttributes(attributes, key: key)
      },
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
    var attributes: KeychainItemAttributes
  }

  private var items: [String: Item] = [:]
  private var subscribers = KeychainSubscribers()
  private let authenticate: Authenticator

  init(entries: [KeychainEntry], authenticate: @escaping Authenticator) {
    for entry in entries {
      items[entry.key] = Item(
        data: entry.data,
        authentication: entry.authentication,
        attributes: entry.attributes
      )
    }
    self.authenticate = authenticate
  }

  func save(
    _ data: Data,
    key: String,
    authentication: KeychainAuthentication,
    attributes: KeychainItemAttributes?
  ) {
    // `nil` keeps the replaced item's attributes (D-13).
    let attributes = attributes?.normalized ?? items[key]?.attributes ?? KeychainItemAttributes()
    items[key] = Item(data: data, authentication: authentication, attributes: attributes)
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

  func rename(key: String, to newKey: String) throws {
    guard let item = items[key] else { throw KeychainError.itemNotFound }
    guard key != newKey else { return }
    items[key] = nil
    items[newKey] = item
    subscribers.yield(nil, for: key)
    // Like a save: a gated item is never sent to streams.
    subscribers.yield(item.authentication == .none ? Secret(item.data) : nil, for: newKey)
  }

  func attributes(key: String) -> KeychainItemAttributes? { items[key]?.attributes }

  func updateAttributes(_ attributes: KeychainItemAttributes, key: String) throws {
    guard items[key] != nil else { throw KeychainError.itemNotFound }
    items[key]?.attributes = attributes.normalized
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
