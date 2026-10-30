# Decisions

Choices the spec (`docs/PLAN.md`) leaves open. Each has a number; code that depends on one cites it.

## D-1 · Clients are declared with `@DependencyClient`
The macro writes the initialiser, labelled methods and an unimplemented default for each endpoint, so
`testValue` is `KeychainClient()`, and a test that reaches an endpoint it didn't override fails, naming it.
Non-throwing endpoints (`exists`, `stream`, `isAvailable`) carry a default return value, so an unimplemented call
records an issue without crashing. The interface (`Keychain`) and the live values (`KeychainLive`) are separate
products: feature modules and their tests never link Security.

## D-2 · macOS uses the data protection keychain by default
`live(…, dataProtection: true)` adds `kSecUseDataProtectionKeychain` on macOS, so items behave as on iOS
(accessibility classes, access groups, access control). It needs the `keychain-access-groups` entitlement;
without it the error is `KeychainError.missingEntitlement`. `swift test` binaries are unsigned, so the live tests
pass `dataProtection: false` (the file-based login keychain).

## D-3 · Deleting a missing item succeeds
`delete` and `deleteKey` are idempotent. Callers (log out, reset) want "absent afterwards", and a throw for an
already-absent item only adds a `try?` at every call site. `load` still throws `itemNotFound`;
`loadIfPresent` returns `nil` instead.

## D-4 · Streams see this client's writes only, and never prompt
There is no public notification for keychain changes, so `stream` yields after writes made through the same
client instance (the live store's actor, or the in-memory actor). Changes by another process, an app extension or
another client instance are not seen. `liveValue` is a `static let`, so one app shares one instance.

The first value is read without a prompt. For an item behind an authentication gate that read is refused, so the
stream yields nothing first and starts with the next change. A save of a gated item yields `nil`, not the value:
a stream must not reveal what a read would gate. `exists`, `keys` and `publicKey` also never prompt; a gated item
"exists".

## D-5 · Save is an upsert; a gated item is replaced, not updated
`SecItemAdd`, and on `errSecDuplicateItem`:
- for an ungated save, `SecItemUpdate` with a no-prompt context (atomic);
- for a gated save, or when the existing item is gated (the update would prompt), delete then add.
If the item disappeared between the add and the update (another process), the add is retried.

## D-6 · Secure Enclave handles live in their own service
The live `SecureEnclaveClient` keeps each key's encrypted handle as a generic password in
`"<service>.secure-enclave"`, account `"<purpose>.<tag>"`. So `KeychainClient.deleteAll()` never deletes keys,
and a signing key and a key-agreement key may share a tag. The handle is stored ungated with the key's
accessibility; the gate is on the private key, enforced by the enclave at each use.

## D-7 · Secure Enclave keys are CryptoKit keys, not `SecKey`s
CryptoKit's `SecureEnclave.P256` types are value types with a portable `dataRepresentation`, and they do signing
and ECDH directly. The trade-off: the keys are not `kSecClassKey` items, so `SecKey`-based APIs can't find them
by tag. Public keys cross the API as X9.63 bytes (`SecureEnclavePublicKey`).

## D-8 · Errors are mapped, never passed through
`errSecUserCanceled`, `errSecAuthFailed`, `errSecInteractionNotAllowed` and any `LAError` become
`authenticationFailed`; `errSecMissingEntitlement` becomes `missingEntitlement`; a malformed peer key or handle of
the wrong purpose becomes `invalidKey`. Other statuses keep their `OSStatus` in `saveFailed`, `loadFailed`,
`deleteFailed`. No case carries bytes, so any error can be logged.

## D-9 · `Secret` is neither `Codable` nor `Hashable`
`Codable` would let a secret slip into JSON; a hash is a fingerprint of the value. `==` is kept (tests need it),
constant-time for `Data` and `String`.

## D-10 · The in-memory doubles simulate prompts with a closure
`inMemory(authenticate:)` takes `(KeychainAuthentication, AuthContext?) async -> Bool`, called on each read of a
gated item (or use of a gated Secure Enclave key). The default lets every read through; a test of the refusal path
passes `{ _, _ in false }`. Prefilled entries keep their key's gate.

## D-11 · Rename moves the account attribute, never the bytes
`rename(_:to:)` changes the item's `kSecAttrAccount` with `SecItemUpdate`, under a context that refuses
interaction, so a gated item moves without a prompt and keeps its protection. The source must exist
(`itemNotFound` otherwise); an item already under the target key is deleted first, like an upsert. Streams see
`nil` on the old key and, on the new key, what a save would send (`nil` for a gated item, D-4). Callers that keep
several items per logical name (one per environment, say) rename each with `keys()`, without reading values.

## D-12 · Typed keys are the only public way in
The string-keyed endpoints (`save`, `load`, `delete`, `rename`, `exists`, `stream`) and the memberwise
initialiser are `package`: `KeychainLive` and the tests, in the same package, build and call them; code outside
cannot, so an account string is spelled once, in a `KeychainKey`. `package` rather than `internal` because
`KeychainLive` is another module, and rather than `@_spi` because an SPI import can be written by anyone.
`deleteAll` and `keys` take no key and stay `public package(set)`: callable, not replaceable. `keys()` returns
accounts (a caller that encodes its own data in accounts parses them); `keys(_:)` maps them to typed keys. A
`KeychainKey` is still made from any string, so a stored item of unknown origin stays reachable.
The cost: a test can no longer replace a single endpoint. The doubles cover it: `testValue` (unimplemented),
`.inMemory(authenticate:prefilling:)` (prompts simulated, D-10), `.noop`, and `.failing(_:)`, which throws one
`KeychainError` on every call (a missing entitlement, a refused prompt).

## D-13 · Items carry a typed label and comment, read and changed without their data
`KeychainItemAttributes` holds an item's `kSecAttrLabel` and `kSecAttrComment`: short, non-secret strings stored
in the clear. A caller keeps there what it must know without reading the secret, such as the list of entries a
vault item holds, so it needs no empty marker items beside it.
- `save(_:for:attributes:)` sets them. `nil`, the default, keeps the attributes of the item the save replaces,
  including a gated item replaced by delete and add (D-5), so updating a value never drops its label.
- `attributes(for:)` queries with `kSecReturnAttributes` and never `kSecReturnData`, under a context that refuses
  interaction: no prompt, even for a gated item or a login-keychain item another code signature created. `nil`
  when there is no item.
- `updateAttributes(_:for:)` is a `SecItemUpdate` of the two attributes only: the data is not read or rewritten,
  the item keeps its protection, and streams see nothing (the value did not change). It replaces both fields:
  `nil` removes one. `itemNotFound` when there is no item, as `rename` (D-11).
- `rename` keeps the attributes. An empty string is stored and read as no value: the keychain can't tell them
  apart once cleared.
- Only label and comment: they are the generic-password attributes a caller may own freely (`kSecAttrGeneric`
  and `kSecAttrDescription` stay unused). There is no public "attributes of every item": a caller lists keys
  with `keys(_:)` and reads the ones it needs, keeping the API typed (D-12).
