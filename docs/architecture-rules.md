# Architecture rules

The mechanical part of `CLAUDE.md` ("Layout", "Rules") and `docs/DECISIONS.md`, enforced by the `Architecture/` package with [swift-llm-check](https://github.com/mackoj/swift-llm-check): `xcrun swift test --package-path Architecture` (macOS). Generated from its rules; do not edit by hand.

## modules

The interface / live split. Read before you add an `import` or a `SecItem` call to `Sources`.

### `Sources/Keychain` never imports Security.

`interface-never-imports-security`: `Keychain` is the interface: clients, typed keys, `Secret`, errors and in-memory doubles. Feature modules and their tests link it without linking Security.framework, and it builds on Linux (CLAUDE.md "Layout", D-1). One `import Security` there breaks both.

**How to fix:** Put the code that needs Security in `Sources/KeychainLive`, inside `#if canImport(Security)`. A type the interface needs a Security mapping for keeps the mapping in `KeychainLive`, like `KeychainAccessibility.cfValue`.

Bad:

```swift
// Sources/Keychain/KeychainAccessibility.swift
import Security
```

Good:

```swift
// Sources/KeychainLive/KeychainStore.swift
#if canImport(Security)
  import Security
  extension KeychainAccessibility { var cfValue: CFString { … } }
#endif
```

### Every file in `Sources/KeychainLive` is wrapped in `#if canImport(Security)`.

`live-code-is-guarded`: The package builds on Linux, where Security does not exist; CI's Linux job builds every target. `KeychainLive` compiles to an empty module there only if each of its files is entirely under the guard (CLAUDE.md "Layout").

**How to fix:** Start the file with `#if canImport(Security)` (add `&& canImport(CryptoKit)` when it uses CryptoKit) and end it with `#endif`, with every import inside.

Bad:

```swift
import Foundation
import Security
actor KeychainStore { … }
```

Good:

```swift
#if canImport(Security)
  import Foundation
  import Security
  actor KeychainStore { … }
#endif
```

### `SecItem*` functions are called only in `KeychainStore.swift`.

`secitem-calls-stay-in-the-store`: `KeychainStore` is the actor that serializes every `SecItem*` call for a service, maps `OSStatus` to `KeychainError` (D-8) and feeds the streams (D-4). A `SecItemAdd` elsewhere races with it, leaks a raw status, and changes an item without telling its subscribers.

**How to fix:** Add a method to `KeychainStore` and call that.

Bad:

```swift
// Sources/KeychainLive/SecureEnclaveClient+Live.swift
let status = SecItemDelete(query as CFDictionary)
```

Good:

```swift
// Sources/KeychainLive/SecureEnclaveClient+Live.swift
try await store.delete(key: key.account)
```

## secrets

Where secret bytes may go. Read before you call `exposeSecret()`, add an error case or log.

### Each `exposeSecret()` call in `Sources` has a `// exposeSecret: <why>` comment.

`expose-secret-says-why`: A value read from the keychain stays in `Secret` until the line that needs the bytes (CLAUDE.md "Secrets"). Each call site is a place a secret leaves its wrapper, so it says why in a comment the reviewer reads; `scripts/expose-audit.sh` also counts the call sites against `scripts/expose-allowlist.txt`.

**How to fix:** Put `// exposeSecret: <why the bytes are needed here>` on the line above the statement, then run `scripts/expose-audit.sh --update`. Better: keep the value wrapped with `Secret.map`.

Bad:

```swift
let data = try key.encode(secret.exposeSecret())
```

Good:

```swift
// exposeSecret: encoding to bytes for storage.
let data = try key.encode(secret.exposeSecret())
```

### `Secret` is never `Codable`, `Encodable`, `Decodable` or `Hashable`.

`secret-is-neither-codable-nor-hashable`: A `Codable` secret ends up in JSON, a plist or a log by accident; a hash of a secret is a fingerprint of it (D-9). Neither the type nor an extension in this package adds them.

**How to fix:** Encode the exposed value at the one call site that must, with an `exposeSecret:` comment. Compare with `==`, which is constant-time for `Data` and `String`.

Bad:

```swift
extension Secret: Codable where Value: Codable {}
```

Good:

```swift
extension Secret: Equatable where Value: Equatable { … }
```

### `KeychainError` cases carry only `OSStatus` codes.

`errors-carry-no-bytes`: An error is logged, reported and shown as is, so no case may carry payload bytes or a value derived from them (CLAUDE.md "Errors", D-8). An `OSStatus` says what failed without saying what was stored.

**How to fix:** Add a case without a payload, or with the `OSStatus`. Keep the item's data out of the error.

Bad:

```swift
case decodingFailed(Data)
```

Good:

```swift
case decodingFailed
```

### The library never prints or logs.

`library-never-logs`: The library handles tokens, passwords and key bytes. `print`, `debugPrint`, `dump`, `NSLog` and `Logger` put whatever they are given in a console or the unified log, where a secret outlives the process. Failures are thrown `KeychainError`s, which the caller may log.

**How to fix:** Throw a `KeychainError`, or return the value to the caller.

Bad:

```swift
print("loaded \(key)")
```

Good:

```swift
throw KeychainError.loadFailed(status)
```

## api

The public surface. Read before you make a client endpoint or a type public.

### A `KeychainClient` endpoint that takes a raw account `String` is not `public`.

`raw-account-endpoints-are-package`: Typed keys are the only public way in (D-12): a `KeychainKey` carries the account, its protection and its serialization together, so a call site can't pair a key with the wrong protection or decoder. The string-keyed closures are `package`, for the package's own implementations.

**How to fix:** Declare the closure `package var`, and add a public typed method in `KeychainClient+Typed.swift` that takes a `KeychainKey<Value>`.

Bad:

```swift
public var load: @Sendable (_ key: String, _ context: AuthContext?) async throws -> Secret<Data>
```

Good:

```swift
package var load: @Sendable (_ key: String, _ context: AuthContext?) async throws -> Secret<Data>
public func load<Value>(for key: KeychainKey<Value>, context: AuthContext? = nil) async throws
```

### An `@unchecked Sendable` conformance has a `//` comment that proves it safe.

`unchecked-sendable-explains-itself`: `@unchecked Sendable` turns off the compiler's data-race check for the type. The comment is the only proof left that sharing it is safe; a doc comment describes the type to its users and is not that proof. Shared mutable state belongs in an `actor`, like `KeychainStore`.

**How to fix:** Prefer a value type or an `actor`. If neither fits, put a `//` comment on the declaration (above it or at the end of its line) that says why sharing it is safe.

Bad:

```swift
/// A handle on an `LAContext`.
public struct AuthContext: @unchecked Sendable {
```

Good:

```swift
/// A handle on an `LAContext`.
public struct AuthContext: @unchecked Sendable {  // LAContext is thread-safe; never mutated.
```

## testing

Swift Testing and the live keychain. Read before you add or skip a test.

### Tests use Swift Testing, never XCTest.

`tests-use-swift-testing`: The suites are Swift Testing only (CLAUDE.md "Tests"): `@Test`, `#expect` and `#require` give one failure style, parameterised tests and parallel runs, and `withDependencies` scopes each test's clients.

**How to fix:** Write a `struct` of `@Test` functions with `#expect` and `#require`; `import Testing`.

Bad:

```swift
import XCTest
final class SecretTests: XCTestCase { func testRedacted() { XCTAssertEqual(…) } }
```

Good:

```swift
import Testing
struct SecretTests { @Test func redacted() { #expect(…) } }
```

### No test or suite is `.disabled`.

`tests-are-not-disabled`: A disabled test still reads as coverage while checking nothing. A test that can't run everywhere is gated on the condition it needs, like the live suites' `.enabled(if: liveTestsEnabled)`, so it runs wherever it can.

**How to fix:** Fix the code or the test, or gate it with `.enabled(if:)` on what it needs.

Bad:

```swift
@Test(.disabled("flaky on CI")) func renameKeepsProtection() async throws {
```

Good:

```swift
@Suite(.enabled(if: liveTestsEnabled && SecureEnclave.isAvailable))
```

### Every suite in `Tests/KeychainLiveTests` is `.enabled(if: liveTestsEnabled …)`.

`live-suites-can-be-skipped`: Live tests use the real keychain. `SKIP_LIVE_KEYCHAIN_TESTS=1` must skip all of them where there is none, or where touching it would prompt (CLAUDE.md "Layout").

**How to fix:** Add `.enabled(if: liveTestsEnabled)` to the suite, with any extra condition after `&&`.

Bad:

```swift
@Suite struct RenameLiveTests {
```

Good:

```swift
@Suite(.enabled(if: liveTestsEnabled)) struct RenameLiveTests {
```

### A live client in a test uses a service name with a fresh `UUID()`.

`live-tests-use-a-fresh-service`: Live tests write to the developer's own login keychain and run in parallel. A fixed service shares items between tests, and with whatever a crashed run left behind; a fresh one per test, emptied at the end (`withLiveKeychain`), shares nothing and leaves nothing.

**How to fix:** Use `withLiveKeychain`, or pass `service: "swift-keychain.tests.\(UUID().uuidString)"`.

Bad:

```swift
let keychain = KeychainClient.live(service: "tests", dataProtection: false)
```

Good:

```swift
let keychain = KeychainClient.live(
  service: "swift-keychain.tests.\(UUID().uuidString)", dataProtection: false)
```
