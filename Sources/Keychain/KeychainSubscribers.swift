import Foundation

/// The `stream` subscribers of one store, by key.
///
/// Owned by an actor (the in-memory store, the live store), which mutates it and yields to it
/// from its own isolation. That serial order is what keeps a stream's first value and the
/// changes after it in order.
package struct KeychainSubscribers {
  private var continuations: [String: [UUID: AsyncStream<Secret<Data>?>.Continuation]] = [:]

  package init() {}

  package mutating func add(
    _ continuation: AsyncStream<Secret<Data>?>.Continuation,
    for key: String
  ) -> UUID {
    let id = UUID()
    continuations[key, default: [:]][id] = continuation
    return id
  }

  package mutating func remove(_ id: UUID, for key: String) {
    continuations[key]?[id] = nil
    if continuations[key]?.isEmpty == true { continuations[key] = nil }
  }

  package func yield(_ value: Secret<Data>?, for key: String) {
    continuations[key]?.values.forEach { $0.yield(value) }
  }

  package func yieldNilToAll() {
    for continuations in continuations.values {
      continuations.values.forEach { $0.yield(nil) }
    }
  }
}
