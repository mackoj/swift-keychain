# Measuring and profiling

The benchmarks live in `Benchmarks/`, a separate package on
[package-benchmark](https://github.com/ordo-one/package-benchmark), so the library never depends on it. Run
everything from the repository root. package-benchmark counts mallocs with jemalloc (`brew install jemalloc`);
set `BENCHMARK_DISABLE_JEMALLOC=true` to build without it, as CI does.

## What is measured

| Group | Benchmarks | Unit |
|---|---|---|
| Typed keys | encode then decode through a `String`, `Data` and `Codable` key | ns per operation |
| `Secret` | constant-time `==` on a 840-byte `String` and 32 bytes of `Data` | ns per operation |
| In-memory client | save and load, `loadIfPresent` of a missing item, `exists`, a stream's first value | ns per operation |
| In-memory client | prefill 100 entries; `keys(_:)` over 100 items, 100 times | µs |
| Live keychain | save (update), load, `exists`, `attributes`, save then delete | µs |

The live benchmarks use the real login keychain, like the live tests: `dataProtection: false`, a service of their
own (`swift-keychain.benchmarks.<UUID>`), emptied after each benchmark, so a run leaves no item behind. Set
`SKIP_LIVE_KEYCHAIN_BENCHMARKS=1` to leave them out. They need the plugin's sandbox off (`--disable-sandbox`): in the
sandbox every keychain call fails with `errSecParam` (-50).

## Measure a change

Save `main`'s numbers before you change code, then compare the same harness after:

```sh
xcrun swift package --package-path Benchmarks --disable-sandbox benchmark --format markdown --no-progress > .build/before.md
# … change the code …
xcrun swift package --package-path Benchmarks --disable-sandbox benchmark --format markdown --no-progress > .build/after.md
xcrun swift run --package-path Benchmarks -c release p50 .build/before.md .build/after.md
```

`p50` prints a Markdown table of each benchmark's median wall clock and mallocs, before → after, ready for the pull
request. Malloc and retain counts are deterministic. Wall clock moves a few percent between runs for the in-memory
benchmarks and up to 2x for the live ones, which wait on `securityd`: rerun before trusting a live difference, and
read its malloc count, which doesn't move.

- `--filter` takes one regular expression per flag (`--filter 'Live.*' --filter 'Secret.*'`).
- The per-operation benchmarks (`scalingFactor: .kilo`) report nanoseconds per operation, marked `*` in
  package-benchmark's tables.

## Profile a benchmark

```sh
Benchmarks/scripts/profile.sh 'Encode and decode, Codable key' 25
```

It runs that one benchmark under Instruments' Time Profiler and prints:

- **Self**: the functions the samples were in. Standard library and system entries say what kind of work dominates
  (`_xzm_malloc` is allocation, `swift_retain` reference counting, `JSONWriter.serializeString` JSON).
- **Inclusive**: the Keychain, KeychainLive and Dependencies functions with the most samples under them, which says
  whose work it is.

The trace stays in `Benchmarks/.build/profiles/` to open in Instruments.

## What has paid off

0.4.1, measured on an M-series Mac, macOS 27, Xcode's Swift 6.4 (p50, before → after):

| Benchmark | Wall clock p50 (µs) | Mallocs p50 |
|---|---|---|
| Live exists | 4215 → 289 (0.07x) | 489 → 260 (0.53x) |
| Live attributes | 3760 → 306 (0.08x) | 476 → 261 (0.55x) |
| Live save, String (update) | 37978 → 29180 (0.77x) | 146559 → 146303 (1.00x) |
| Live load, String | 2210 → 2230 (1.01x) | 656 → 660 (1.01x) |
| Secret ==, String | 0.400 → 0.112 (0.28x) | 4 → 0 |
| Secret ==, Data | 0.080 → 0.079 (0.99x) | 0 → 0 |

(A second run measured `Live exists` at 1797 → 303 µs and `Live attributes` at 1770 → 356 µs: the live wall clock
varies, the ratio and the malloc counts hold.)

- **Make the no-prompt `LAContext` once per store.** Every query that must not prompt (`exists`, `keys`,
  `attributes`, `updateAttributes`, `rename`, a stream's first value, the update path of `save`) passed a new
  `LAContext` with `interactionNotAllowed`. Creating one costs more than the keychain query: `exists` went from
  ~1.8–4.2 ms to ~0.3 ms, below a plain `load`. The context is never evaluated, so sharing it shares no credential.
- **Compare a `Secret<String>` in place.** `==` copied both strings into a `Data` before the constant-time loop;
  it now compares their UTF-8 storage with `withUTF8`: no allocation, a copy of the secret fewer in memory.
- **Not worth it:** a `JSONEncoder`/`JSONDecoder` per key instead of per call measured 4–8% on the `Codable`
  round trip: the time is in JSON itself (`JSONWriter`, metadata lookups). Left as is.
- What is left is in Security: a live save is ~25–35 ms and ~150 000 mallocs inside `SecItemAdd` / `SecItemUpdate`
  on the file-based login keychain, the same before and after.
