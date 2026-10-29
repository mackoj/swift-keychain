# swift-keychain: specification

## 1. Goal

A small, testable, type-safe way for Swift apps to keep secrets in the keychain and to use keys held in the
Secure Enclave, built as two swift-dependencies clients so that features using them test without a device, a
keychain or Security.framework.

It is a rewrite, not a fork, of the ideas in `dktunited/swift-dependencies-keychain`: typed keys, an opaque
`Secret`, an interface/live split. It carries no dependency on, or naming from, that project.

## 2. What it provides

### 2.1 `KeychainClient` (generic passwords)
- Byte-level endpoints declared with `@DependencyClient`: `save`, `load`, `delete`, `rename`, `attributes`,
  `updateAttributes`, `deleteAll`, `exists`, `keys`, `stream`. The string-keyed ones and the memberwise initialiser are `package` (D-12);
  `deleteAll()` and `keys()` are public to call.
- The public API, on `KeychainKey<Value>`: `save(_:for:attributes:)`, `load(for:context:)`,
  `loadIfPresent(for:context:)`, `delete(for:)`, `rename(_:to:)`, `attributes(for:)`, `updateAttributes(_:for:)`,
  `exists(for:)`, `keys(_:)`, `stream(for:)`.
- `KeychainItemAttributes`: an item's label and comment, read and changed without its data (D-13).
- `KeychainKey` initialisers for `Data` (as is), `String` (UTF-8), `Codable` (JSON) and custom closures. A key
  carries its accessibility and authentication gate.
- Implementations: `.live(service:accessGroup:dataProtection:)` (and `liveValue`), `.inMemory(authenticate:
  prefilling:)`, `.noop`, `.failing(_:)`, and the macro's unimplemented `testValue`.

### 2.2 `SecureEnclaveClient` (P-256 keys)
- Endpoints: `isAvailable`, `createKey`, `publicKey`, `deleteKey`, `sign`, `sharedSecret`.
- Typed keys `SecureEnclaveKey<Signing>` and `SecureEnclaveKey<KeyAgreement>`: the compiler rejects signing with
  a key-agreement key.
- Each use of a private key can be gated (`KeychainAuthentication`), enforced by the enclave.
- Implementations: `.live(…)` (CryptoKit) and `.inMemory(authenticate:)` (software P-256 keys, real signatures).

### 2.3 Shared types
- `Secret<Value>`: redacted description and mirror, not `Codable`, not `Hashable`, constant-time `==` for `Data`
  and `String`, `map`.
- `KeychainError`: no case carries bytes.
- `AuthContext`: a `Sendable` `LAContext`, so one evaluated prompt can cover several reads.

## 3. Platforms

iOS 16, macOS 13, tvOS 16, watchOS 9, visionOS 1. The interface module and its in-memory keychain build and test
on Linux; the Secure Enclave double needs CryptoKit (Apple platforms).

## 4. Non-goals (for now)

- iCloud Keychain sync (`kSecAttrSynchronizable`), internet passwords, certificates and identities.
- `SecKey` interop for Secure Enclave keys (D-7).
- Observing changes made by another process (D-4).
- A Linux live keychain (libsecret).

Each may become a task in `tasks/todo.md`; moving one out of this list needs a D-number.

## 5. Quality bar

- Every public behaviour has an in-memory test; every live-store behaviour has a live test on macOS.
- CI on every push and PR: macOS (build, all tests, lint, secret scan, `exposeSecret` audit) and Linux
  (interface tests).
- No new `exposeSecret()` without updating `scripts/expose-allowlist.txt`.
