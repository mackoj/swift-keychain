# Todo

## v0.1 · foundation
- [x] Package: `Keychain` (interface) and `KeychainLive` products, swift-dependencies `@DependencyClient` clients
- [x] `KeychainClient`: typed keys, `Secret`, in-memory and no-op doubles, live store, streams (D-3, D-4, D-5)
- [x] `SecureEnclaveClient`: signing and key agreement, typed purposes, in-memory double, live CryptoKit store (D-6, D-7)
- [x] Harness: `CLAUDE.md`, `docs/PLAN.md`, `docs/DECISIONS.md`, scripts, swift-format, CI (macOS + Linux)
- [ ] First CI run green on GitHub (macOS live tests on a hosted runner; Linux interface tests)
- [x] Tag `0.1.0`

## Next
- [x] `rename(_:to:)`: move an item to another key without reading it (D-11)
- [ ] DocC catalog with the README's guide as articles; publish with GitHub Pages
- [ ] Live tests on iOS Simulator through `xcodebuild test` (data protection keychain, entitled host app)
- [ ] `SecureEnclavePublicKey` helpers: PEM / DER (SubjectPublicKeyInfo) export for servers
- [ ] Optional: iCloud Keychain sync (`synchronizable` on `KeychainKey`), needs a D-number (PLAN §4)
- [ ] Optional: migrate items from another service or access group (`KeychainClient.migrate(from:)`)
