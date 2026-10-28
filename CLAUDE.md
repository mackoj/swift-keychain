# swift-keychain: working notes for agents

A Swift package: a testable keychain and Secure Enclave, as two
[swift-dependencies](https://github.com/pointfreeco/swift-dependencies) clients.

## Read first
- **Spec:** `docs/PLAN.md` says what the package is and is not. `docs/DECISIONS.md` records each choice the
  spec leaves open, as D-numbers. Cite the D-number in code comments that depend on one; add a D-number when you
  make a new choice.
- **Tasks:** `tasks/todo.md` is the backlog. Tick an item in the PR that finishes it.
- **Usage:** `README.md` is the user-facing guide. Keep its examples compiling: they mirror `Tests/KeychainTests`.

## Layout
- `Sources/Keychain`: the interface. Clients (`@DependencyClient`), typed keys, `Secret`, errors, in-memory
  doubles. **Never imports Security.** Builds on Linux.
- `Sources/KeychainLive`: `liveValue`s on Security.framework and CryptoKit. Everything in `#if canImport(Security)`.
- `Tests/KeychainTests`: in-memory and dependency tests, run everywhere. `Tests/KeychainLiveTests`: the real macOS
  keychain and Secure Enclave, unsigned binary (`dataProtection: false`); skipped with `SKIP_LIVE_KEYCHAIN_TESTS=1`.

## Rules
- **Secrets:** a value read from the keychain stays in `Secret` until the line that needs the bytes. Each
  `exposeSecret()` has a `// exposeSecret: <why>` comment and is listed in `scripts/expose-allowlist.txt`;
  `scripts/expose-audit.sh` fails on any new call site. Adding one means updating the list in the same PR, which
  puts it in front of the reviewer.
- **Errors:** `KeychainError` cases never carry payload bytes.
- **No prompts behind the caller's back:** `exists`, `keys`, `publicKey` and a stream's first value never show
  an authentication prompt (D-4).
- **Tests:** Swift Testing only. Given / When / Then layout, blank-line separated. A behaviour change in the
  live store needs a live test, and the in-memory store must behave the same (same errors, same stream order).
- **Style:** `.swift-format` (2 spaces, 100 columns). Match the surrounding code's comment density: doc comments
  on public API, a line of *why* where code is not obvious, nothing else.

## Commands
- **Toolchain:** always `xcrun swift …` / `xcodebuild`. A bare `swift` may be swiftly's open-source toolchain.
- `scripts/test.sh [filter]`: tests, with a summary in `build/test-summary.md`. Pipe long logs through
  `xcsift -f toon` when installed.
- `scripts/ci.sh`: the full gate CI runs: build, tests, swift-format lint, secret scan, `exposeSecret` audit.
  `scripts/ci.sh --platforms` also builds for iOS, tvOS, watchOS and visionOS.
- `scripts/format.sh`: format in place.

## Workflow
- One branch and one PR per task; squash merge. CI (`.github/workflows/ci.yml`) must be green: macOS (full
  gate) and Linux (interface tests).
- **Attribution:** commits and PRs carry no Claude trailers or footers.
