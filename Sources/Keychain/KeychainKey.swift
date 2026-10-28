import Foundation

/// A typed address for a keychain item: its account name, protection and serialization.
///
/// Declare keys once, as static constants, so call sites never spell raw strings:
///
/// ```swift
/// extension KeychainKey where Value == String {
///   static let authToken = KeychainKey("auth.token")
/// }
/// ```
public struct KeychainKey<Value: Sendable>: Sendable {
  /// The `kSecAttrAccount` of the item.
  public let rawValue: String
  /// When the item can be read. Applied on save.
  public let accessibility: KeychainAccessibility
  /// The authentication gate on reads. Applied on save.
  public let authentication: KeychainAuthentication
  /// Turns a value into the stored bytes.
  public let encode: @Sendable (Value) throws -> Data
  /// Turns stored bytes back into a value.
  public let decode: @Sendable (Data) throws -> Value

  /// A key with custom serialization, for a `Value` that is neither `Data`, `String` nor `Codable`.
  public init(
    _ rawValue: String,
    accessibility: KeychainAccessibility = .afterFirstUnlockThisDeviceOnly,
    authentication: KeychainAuthentication = .none,
    encode: @escaping @Sendable (Value) throws -> Data,
    decode: @escaping @Sendable (Data) throws -> Value
  ) {
    self.rawValue = rawValue
    self.accessibility = accessibility
    self.authentication = authentication
    self.encode = encode
    self.decode = decode
  }
}

extension KeychainKey where Value == Data {
  /// A key whose bytes are stored as is.
  public init(
    _ rawValue: String,
    accessibility: KeychainAccessibility = .afterFirstUnlockThisDeviceOnly,
    authentication: KeychainAuthentication = .none
  ) {
    self.init(
      rawValue,
      accessibility: accessibility,
      authentication: authentication,
      encode: { $0 },
      decode: { $0 }
    )
  }
}

extension KeychainKey where Value == String {
  /// A key whose strings are stored as UTF-8.
  public init(
    _ rawValue: String,
    accessibility: KeychainAccessibility = .afterFirstUnlockThisDeviceOnly,
    authentication: KeychainAuthentication = .none
  ) {
    self.init(
      rawValue,
      accessibility: accessibility,
      authentication: authentication,
      encode: { Data($0.utf8) },
      decode: { data in
        guard let string = String(data: data, encoding: .utf8) else {
          throw KeychainError.decodingFailed
        }
        return string
      }
    )
  }
}

extension KeychainKey where Value: Codable {
  /// A key whose values are stored as JSON.
  public init(
    _ rawValue: String,
    accessibility: KeychainAccessibility = .afterFirstUnlockThisDeviceOnly,
    authentication: KeychainAuthentication = .none
  ) {
    self.init(
      rawValue,
      accessibility: accessibility,
      authentication: authentication,
      encode: { value in
        do { return try JSONEncoder().encode(value) } catch { throw KeychainError.encodingFailed }
      },
      decode: { data in
        do { return try JSONDecoder().decode(Value.self, from: data) } catch {
          throw KeychainError.decodingFailed
        }
      }
    )
  }
}
