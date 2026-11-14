import LLMCheck

extension Rule {
  static let interfaceNeverImportsSecurity = Rule(
    id: "interface-never-imports-security",
    title: "`Sources/Keychain` never imports Security.",
    category: .modules,
    rationale: """
      `Keychain` is the interface: clients, typed keys, `Secret`, errors and in-memory doubles. \
      Feature modules and their tests link it without linking Security.framework, and it builds on \
      Linux (CLAUDE.md "Layout", D-1). One `import Security` there breaks both.
      """,
    howToFix: """
      Put the code that needs Security in `Sources/KeychainLive`, inside `#if canImport(Security)`. \
      A type the interface needs a Security mapping for keeps the mapping in `KeychainLive`, like \
      `KeychainAccessibility.cfValue`.
      """,
    badExample: """
      // Sources/Keychain/KeychainAccessibility.swift
      import Security
      """,
    goodExample: """
      // Sources/KeychainLive/KeychainStore.swift
      #if canImport(Security)
        import Security
        extension KeychainAccessibility { var cfValue: CFString { … } }
      #endif
      """
  )

  static let liveCodeIsGuarded = Rule(
    id: "live-code-is-guarded",
    title: "Every file in `Sources/KeychainLive` is wrapped in `#if canImport(Security)`.",
    category: .modules,
    rationale: """
      The package builds on Linux, where Security does not exist; CI's Linux job builds every \
      target. `KeychainLive` compiles to an empty module there only if each of its files is \
      entirely under the guard (CLAUDE.md "Layout").
      """,
    howToFix: """
      Start the file with `#if canImport(Security)` (add `&& canImport(CryptoKit)` when it uses \
      CryptoKit) and end it with `#endif`, with every import inside.
      """,
    badExample: """
      import Foundation
      import Security
      actor KeychainStore { … }
      """,
    goodExample: """
      #if canImport(Security)
        import Foundation
        import Security
        actor KeychainStore { … }
      #endif
      """
  )

  static let secItemCallsStayInTheStore = Rule(
    id: "secitem-calls-stay-in-the-store",
    title: "`SecItem*` functions are called only in `KeychainStore.swift`.",
    category: .modules,
    rationale: """
      `KeychainStore` is the actor that serializes every `SecItem*` call for a service, maps \
      `OSStatus` to `KeychainError` (D-8) and feeds the streams (D-4). A `SecItemAdd` elsewhere \
      races with it, leaks a raw status, and changes an item without telling its subscribers.
      """,
    howToFix: "Add a method to `KeychainStore` and call that.",
    badExample: """
      // Sources/KeychainLive/SecureEnclaveClient+Live.swift
      let status = SecItemDelete(query as CFDictionary)
      """,
    goodExample: """
      // Sources/KeychainLive/SecureEnclaveClient+Live.swift
      try await store.delete(key: key.account)
      """
  )

  static let exposeSecretSaysWhy = Rule(
    id: "expose-secret-says-why",
    title: "Each `exposeSecret()` call in `Sources` has a `// exposeSecret: <why>` comment.",
    category: .secrets,
    rationale: """
      A value read from the keychain stays in `Secret` until the line that needs the bytes \
      (CLAUDE.md "Secrets"). Each call site is a place a secret leaves its wrapper, so it says why \
      in a comment the reviewer reads; `scripts/expose-audit.sh` also counts the call sites \
      against `scripts/expose-allowlist.txt`.
      """,
    howToFix: """
      Put `// exposeSecret: <why the bytes are needed here>` on the line above the statement, then \
      run `scripts/expose-audit.sh --update`. Better: keep the value wrapped with `Secret.map`.
      """,
    badExample: """
      let data = try key.encode(secret.exposeSecret())
      """,
    goodExample: """
      // exposeSecret: encoding to bytes for storage.
      let data = try key.encode(secret.exposeSecret())
      """
  )

  static let secretIsNeitherCodableNorHashable = Rule(
    id: "secret-is-neither-codable-nor-hashable",
    title: "`Secret` is never `Codable`, `Encodable`, `Decodable` or `Hashable`.",
    category: .secrets,
    rationale: """
      A `Codable` secret ends up in JSON, a plist or a log by accident; a hash of a secret is a \
      fingerprint of it (D-9). Neither the type nor an extension in this package adds them.
      """,
    howToFix: """
      Encode the exposed value at the one call site that must, with an `exposeSecret:` comment. \
      Compare with `==`, which is constant-time for `Data` and `String`.
      """,
    badExample: "extension Secret: Codable where Value: Codable {}",
    goodExample: "extension Secret: Equatable where Value: Equatable { … }"
  )

  static let errorsCarryNoBytes = Rule(
    id: "errors-carry-no-bytes",
    title: "`KeychainError` cases carry only `OSStatus` codes.",
    category: .secrets,
    rationale: """
      An error is logged, reported and shown as is, so no case may carry payload bytes or a value \
      derived from them (CLAUDE.md "Errors", D-8). An `OSStatus` says what failed without saying \
      what was stored.
      """,
    howToFix: """
      Add a case without a payload, or with the `OSStatus`. Keep the item's data out of the error.
      """,
    badExample: "case decodingFailed(Data)",
    goodExample: "case decodingFailed"
  )

  static let libraryNeverLogs = Rule(
    id: "library-never-logs",
    title: "The library never prints or logs.",
    category: .secrets,
    rationale: """
      The library handles tokens, passwords and key bytes. `print`, `debugPrint`, `dump`, `NSLog` \
      and `Logger` put whatever they are given in a console or the unified log, where a secret \
      outlives the process. Failures are thrown `KeychainError`s, which the caller may log.
      """,
    howToFix: "Throw a `KeychainError`, or return the value to the caller.",
    badExample: #"print("loaded \(key)")"#,
    goodExample: "throw KeychainError.loadFailed(status)"
  )

  static let rawAccountEndpointsArePackage = Rule(
    id: "raw-account-endpoints-are-package",
    title: "A `KeychainClient` endpoint that takes a raw account `String` is not `public`.",
    category: .api,
    rationale: """
      Typed keys are the only public way in (D-12): a `KeychainKey` carries the account, its \
      protection and its serialization together, so a call site can't pair a key with the wrong \
      protection or decoder. The string-keyed closures are `package`, for the package's own \
      implementations.
      """,
    howToFix: """
      Declare the closure `package var`, and add a public typed method in \
      `KeychainClient+Typed.swift` that takes a `KeychainKey<Value>`.
      """,
    badExample: """
      public var load: @Sendable (_ key: String, _ context: AuthContext?) async throws -> Secret<Data>
      """,
    goodExample: """
      package var load: @Sendable (_ key: String, _ context: AuthContext?) async throws -> Secret<Data>
      public func load<Value>(for key: KeychainKey<Value>, context: AuthContext? = nil) async throws
      """
  )

  static let uncheckedSendableExplainsItself = Rule(
    id: "unchecked-sendable-explains-itself",
    title: "An `@unchecked Sendable` conformance has a `//` comment that proves it safe.",
    category: .api,
    rationale: """
      `@unchecked Sendable` turns off the compiler's data-race check for the type. The comment is \
      the only proof left that sharing it is safe; a doc comment describes the type to its users \
      and is not that proof. Shared mutable state belongs in an `actor`, like `KeychainStore`.
      """,
    howToFix: """
      Prefer a value type or an `actor`. If neither fits, put a `//` comment on the declaration \
      (above it or at the end of its line) that says why sharing it is safe.
      """,
    badExample: """
      /// A handle on an `LAContext`.
      public struct AuthContext: @unchecked Sendable {
      """,
    goodExample: """
      /// A handle on an `LAContext`.
      public struct AuthContext: @unchecked Sendable {  // LAContext is thread-safe; never mutated.
      """
  )
}

extension Rule {
  static let testsUseSwiftTesting = Rule(
    id: "tests-use-swift-testing",
    title: "Tests use Swift Testing, never XCTest.",
    category: .testing,
    rationale: """
      The suites are Swift Testing only (CLAUDE.md "Tests"): `@Test`, `#expect` and `#require` \
      give one failure style, parameterised tests and parallel runs, and `withDependencies` scopes \
      each test's clients.
      """,
    howToFix: """
      Write a `struct` of `@Test` functions with `#expect` and `#require`; `import Testing`.
      """,
    badExample: """
      import XCTest
      final class SecretTests: XCTestCase { func testRedacted() { XCTAssertEqual(…) } }
      """,
    goodExample: """
      import Testing
      struct SecretTests { @Test func redacted() { #expect(…) } }
      """
  )

  static let testsAreNotDisabled = Rule(
    id: "tests-are-not-disabled",
    title: "No test or suite is `.disabled`.",
    category: .testing,
    rationale: """
      A disabled test still reads as coverage while checking nothing. A test that can't run \
      everywhere is gated on the condition it needs, like the live suites' \
      `.enabled(if: liveTestsEnabled)`, so it runs wherever it can.
      """,
    howToFix: "Fix the code or the test, or gate it with `.enabled(if:)` on what it needs.",
    badExample: #"@Test(.disabled("flaky on CI")) func renameKeepsProtection() async throws {"#,
    goodExample: "@Suite(.enabled(if: liveTestsEnabled && SecureEnclave.isAvailable))"
  )

  static let liveSuitesCanBeSkipped = Rule(
    id: "live-suites-can-be-skipped",
    title: "Every suite in `Tests/KeychainLiveTests` is `.enabled(if: liveTestsEnabled …)`.",
    category: .testing,
    rationale: """
      Live tests use the real keychain. `SKIP_LIVE_KEYCHAIN_TESTS=1` must skip all of them where \
      there is none, or where touching it would prompt (CLAUDE.md "Layout").
      """,
    howToFix: """
      Add `.enabled(if: liveTestsEnabled)` to the suite, with any extra condition after `&&`.
      """,
    badExample: "@Suite struct RenameLiveTests {",
    goodExample: "@Suite(.enabled(if: liveTestsEnabled)) struct RenameLiveTests {"
  )

  static let liveTestsUseAFreshService = Rule(
    id: "live-tests-use-a-fresh-service",
    title: "A live client in a test uses a service name with a fresh `UUID()`.",
    category: .testing,
    rationale: """
      Live tests write to the developer's own login keychain and run in parallel. A fixed service \
      shares items between tests, and with whatever a crashed run left behind; a fresh one per \
      test, emptied at the end (`withLiveKeychain`), shares nothing and leaves nothing.
      """,
    howToFix: #"""
      Use `withLiveKeychain`, or pass `service: "swift-keychain.tests.\(UUID().uuidString)"`.
      """#,
    badExample: #"let keychain = KeychainClient.live(service: "tests", dataProtection: false)"#,
    goodExample: """
      let keychain = KeychainClient.live(
        service: "swift-keychain.tests.\\(UUID().uuidString)", dataProtection: false)
      """
  )
}

/// Every rule, in the order `docs/architecture-rules.md` lists them.
let allRules: [Rule] = [
  .interfaceNeverImportsSecurity, .liveCodeIsGuarded, .secItemCallsStayInTheStore,
  .exposeSecretSaysWhy, .secretIsNeitherCodableNorHashable, .errorsCarryNoBytes, .libraryNeverLogs,
  .rawAccountEndpointsArePackage, .uncheckedSendableExplainsItself,
  .testsUseSwiftTesting, .testsAreNotDisabled, .liveSuitesCanBeSkipped, .liveTestsUseAFreshService,
]
