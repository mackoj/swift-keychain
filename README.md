# swift-keychain

A testable, type-safe keychain and Secure Enclave for Swift, as two
[swift-dependencies](https://github.com/pointfreeco/swift-dependencies) clients.

- **Typed keys.** A `KeychainKey<Value>` knows its account, protection and serialization; call sites never
  spell a raw string.
- **Opaque secrets.** Values come back as `Secret<Value>`, which prints as `Secret<String>(redacted)`, isn't
  `Codable`, and compares in constant time. `exposeSecret()` is the one way out, and CI tracks every call site.
- **Secure Enclave.** P-256 signing and key agreement with keys that never leave the device, typed by purpose.
- **Testable.** `@DependencyClient` clients: the test value fails on any call you didn't expect; in-memory doubles
  behave like the real store, prompts included.

## Installation

```swift
.package(url: "https://github.com/mackoj/swift-keychain", from: "0.1.0"),
```

| Product | Add it to | Links |
|---|---|---|
| `Keychain` | every module that reads or writes secrets, and their tests | Dependencies |
| `KeychainLive` | the app target only | Security, CryptoKit |

Without `KeychainLive` in the app, swift-dependencies reports a missing live value at the first use.

## Keychain

### Declare keys

```swift
import Keychain

extension KeychainKey where Value == String {
  static let authToken = KeychainKey("auth.token")
  static let vaultPassword = KeychainKey("vault.password", authentication: .biometricOrPasscode)
}

extension KeychainKey where Value == Data {
  static let encryptionKey = KeychainKey("crypto.encryption-key", accessibility: .whenUnlockedThisDeviceOnly)
}

struct Credentials: Codable, Sendable { var username: String; var pin: String }

extension KeychainKey where Value == Credentials {
  static let credentials = KeychainKey("user.credentials")  // stored as JSON
}
```

`String` keys store UTF-8, `Data` keys store bytes as is, `Codable` keys store JSON. For anything else, pass
`encode:` and `decode:`. The default accessibility is `.afterFirstUnlockThisDeviceOnly`.

### Use it

```swift
import Dependencies
import Keychain

struct Session {
  @Dependency(\.keychain) var keychain

  func logIn(token: String) async throws {
    try await keychain.save(Secret(token), for: .authToken)
  }

  func bearer() async throws -> String {
    // exposeSecret: the header needs the token.
    "Bearer \(try await keychain.load(for: .authToken).exposeSecret())"
  }

  func logOut() async throws {
    try await keychain.deleteAll()
  }
}
```

| Method | Behaviour |
|---|---|
| `save(_:for:)` | Upsert, with the key's protection. |
| `load(for:context:)` | Throws `.itemNotFound` when absent. |
| `loadIfPresent(for:context:)` | `nil` when absent. |
| `delete(for:)`, `deleteAll()` | Succeed when there is nothing to delete. `deleteAll` touches this service only. |
| `exists(for:)`, `keys()` | Never prompt, even for protected items. |
| `stream(for:)` | The current value, then each change made through this client. |

### Protected items

A key with `authentication: .biometric`, `.biometricCurrentSet`, `.biometricOrPasscode` or `.devicePasscode` is
saved with a `SecAccessControl`; the system prompts on each read. To cover several reads with one prompt, evaluate
an `LAContext` yourself and pass it:

```swift
let context = LAContext()
try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Unlock your vault")
let password = try await keychain.load(for: .vaultPassword, context: AuthContext(context))
```

A cancelled or failed prompt throws `KeychainError.authenticationFailed`.

### Configuration

`liveValue` uses the main bundle identifier as service. For an access group shared with extensions:

```swift
// App entry point
prepareDependencies {
  $0.keychain = .live(service: "com.example.app", accessGroup: "TEAMID.com.example.shared")
}
```

On macOS, the live client uses the data protection keychain, which needs the `keychain-access-groups`
entitlement. For an unsigned tool, pass `dataProtection: false`.

## Secure Enclave

```swift
import Keychain

extension SecureEnclaveKey<Signing> {
  static let deviceIdentity = SecureEnclaveKey("device.identity")
  static let paymentApproval = SecureEnclaveKey("payment.approval", authentication: .biometricCurrentSet)
}

extension SecureEnclaveKey<KeyAgreement> {
  static let sessionAgreement = SecureEnclaveKey("session.agreement")
}

struct DeviceRegistration {
  @Dependency(\.secureEnclave) var secureEnclave

  func register() async throws -> SecureEnclavePublicKey {
    guard secureEnclave.isAvailable() else { throw KeychainError.secureEnclaveUnavailable }
    return try await secureEnclave.publicKeyCreatingIfNeeded(for: .deviceIdentity)
  }

  func approve(_ payment: Data) async throws -> Data {
    try await secureEnclave.sign(payment, with: .paymentApproval)  // DER ECDSA over SHA-256
  }
}
```

- `createKey` replaces any key with the same tag; `publicKeyCreatingIfNeeded` creates one only when missing.
- `sharedSecret(with:using:)` returns the raw ECDH secret as `Secret<Data>`; derive a key from it with HKDF.
- `publicKey.isValidSignature(_:for:)` verifies a signature.
- `sign` only takes a `SecureEnclaveKey<Signing>`, `sharedSecret` a `SecureEnclaveKey<KeyAgreement>`.

The private key never leaves the enclave; the keychain stores its encrypted handle, in the service
`"<service>.secure-enclave"`, so `KeychainClient.deleteAll()` leaves keys alone. The simulator has no
Secure Enclave: `isAvailable()` is `false` and `createKey` throws `.secureEnclaveUnavailable`.

## Testing

```swift
import DependenciesTestSupport
import Keychain
import Testing

@Suite(.dependencies { $0.keychain = .inMemory() })
struct SessionTests {
  @Test func bearerUsesTheSavedToken() async throws {
    let session = Session()

    try await session.logIn(token: "t0k3n")

    #expect(try await session.bearer() == "Bearer t0k3n")
  }
}
```

| Double | Use |
|---|---|
| `KeychainClient()` / `testValue` | Default in tests. Any call fails the test, naming the endpoint. |
| `.inMemory(authenticate:prefilling:)` | A working store. `authenticate` decides each simulated prompt. |
| `.noop` | Accepts everything, stores nothing. |
| `SecureEnclaveClient.inMemory(authenticate:)` | Software P-256 keys; signatures verify. |

```swift
// Prefilled, with every prompt refused
let keychain = try KeychainClient.inMemory(authenticate: { _, _ in false }) {
  try KeychainEntry(Secret("open sesame"), for: .vaultPassword)
}
await #expect(throws: KeychainError.authenticationFailed) {
  try await keychain.load(for: .vaultPassword)
}

// One endpoint stubbed
withDependencies {
  $0.keychain.load = { @Sendable _, _ in throw KeychainError.authenticationFailed }
} operation: { … }
```

Previews get in-memory clients automatically.

## Design notes

`docs/PLAN.md` is the specification, `docs/DECISIONS.md` the choices behind it (idempotent delete, what streams
see, how a protected item is replaced, where Secure Enclave handles live). Contributors and coding agents start
from `CLAUDE.md`.

## Development

```sh
scripts/test.sh               # tests (SKIP_LIVE_KEYCHAIN_TESTS=1 skips the real keychain)
scripts/ci.sh --platforms     # the full gate CI runs
scripts/format.sh             # swift-format in place
```
