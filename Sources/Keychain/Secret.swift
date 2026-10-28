import Foundation

/// A wrapper for sensitive material: tokens, passwords, key bytes.
///
/// `Secret` is deliberately awkward to misuse:
/// - `description`, `debugDescription` and `dump` render as `Secret<Value>(redacted)`.
/// - It is not `Codable`, so it can't end up in JSON or a plist by accident.
/// - It is not `Hashable`: a hash of a secret is a fingerprint of it.
/// - Reading the value takes `exposeSecret()`. Every call site is a greppable audit point
///   (`scripts/expose-audit.sh` lists them).
/// - `==` is constant-time for `Data` and `String` payloads.
public struct Secret<Value: Sendable>: Sendable {
  @usableFromInline let value: Value

  @inlinable
  public init(_ value: Value) { self.value = value }

  /// The escape hatch. Treat every call site as a security review item.
  @inlinable
  public func exposeSecret() -> Value { value }

  /// Transforms the wrapped value without exposing it to the caller's scope.
  @inlinable
  public func map<NewValue: Sendable>(
    _ transform: (Value) throws -> NewValue
  ) rethrows -> Secret<NewValue> {
    Secret<NewValue>(try transform(value))
  }
}

extension Secret: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
  public var description: String { "Secret<\(Value.self)>(redacted)" }
  public var debugDescription: String { description }
  public var customMirror: Mirror {
    Mirror(self, children: ["value": "<redacted>"], displayStyle: .struct)
  }
}

extension Secret: Equatable where Value: Equatable {
  public static func == (lhs: Self, rhs: Self) -> Bool {
    if let l = lhs.value as? Data, let r = rhs.value as? Data {
      return constantTimeEquals(l, r)
    }
    if let l = lhs.value as? String, let r = rhs.value as? String {
      return constantTimeEquals(Data(l.utf8), Data(r.utf8))
    }
    return lhs.value == rhs.value
  }
}

/// Compares two byte buffers in time that depends only on their length.
@usableFromInline
func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
  guard a.count == b.count else { return false }
  var diff: UInt8 = 0
  a.withUnsafeBytes { (a: UnsafeRawBufferPointer) in
    b.withUnsafeBytes { (b: UnsafeRawBufferPointer) in
      for i in 0..<a.count { diff |= a[i] ^ b[i] }
    }
  }
  return diff == 0
}
