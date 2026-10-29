/// Short, non-secret strings stored with a keychain item, readable without its data.
///
/// `attributes(for:)` reads them without the item's data, so it never prompts, even for a gated
/// item, and `updateAttributes(_:for:)` changes them without rewriting the data (D-13). They are
/// stored in the clear: never put a secret in them.
///
/// ```swift
/// try await keychain.save(Secret(vault), for: .vault, attributes: .init(comment: "github\nstripe"))
/// let accounts = try await keychain.attributes(for: .vault)?.comment
/// ```
public struct KeychainItemAttributes: Sendable, Hashable {
  /// The item's label (`kSecAttrLabel`): the name Keychain Access shows.
  public var label: String?
  /// The item's comment (`kSecAttrComment`).
  public var comment: String?

  /// Attributes with the given label and comment. An empty string is stored as no value.
  public init(label: String? = nil, comment: String? = nil) {
    self.label = label
    self.comment = comment
  }

  /// Empty strings as `nil`: the keychain can't tell an empty attribute from a missing one (D-13).
  package var normalized: KeychainItemAttributes {
    KeychainItemAttributes(
      label: label?.isEmpty == true ? nil : label,
      comment: comment?.isEmpty == true ? nil : comment
    )
  }
}
