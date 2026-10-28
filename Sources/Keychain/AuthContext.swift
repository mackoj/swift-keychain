#if canImport(LocalAuthentication)
  import LocalAuthentication

  /// A `Sendable` handle on an `LAContext`, passed to reads of protected items and to
  /// Secure Enclave operations.
  ///
  /// Evaluate the context once, then pass it to several reads to show a single prompt:
  ///
  /// ```swift
  /// let context = LAContext()
  /// context.touchIDAuthenticationAllowableReuseDuration = 10
  /// try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock your vault")
  /// let token = try await keychain.load(for: .vaultKey, context: AuthContext(context))
  /// ```
  ///
  /// Without a context, the system prompts on each read of a protected item.
  public struct AuthContext: @unchecked Sendable {
    // `LAContext` is thread-safe; this wrapper never mutates it.
    public let context: LAContext

    public init(_ context: LAContext) {
      self.context = context
    }
  }
#else
  /// Placeholder on platforms without LocalAuthentication (Linux). Authentication gates are
  /// simulated by the in-memory clients only.
  public struct AuthContext: Sendable {
    public init() {}
  }
#endif
