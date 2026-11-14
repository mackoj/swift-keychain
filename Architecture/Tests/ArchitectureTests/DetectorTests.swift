import LLMCheck
import Testing

/// Each detector on snippets: it finds what its rule forbids and nothing its rule allows.
@Suite struct DetectorTests {
  func scope(_ source: String, at path: String = "Sources/Keychain/File.swift") -> Scope {
    Scope(files: [SourceFile(path: path, source: source)])
  }

  @Test func securityImportsAreFound() {
    let found = Detect.securityImports(
      in: scope(
        """
        import Foundation
        import Security
        #if canImport(Security)
        import Security
        #endif
        // import Security
        """
      )
    )
    #expect(found.map(\.location.line) == [2, 4])
  }

  @Test func secItemCallsOutsideTheStoreAreFound() {
    let found = Detect.secItemCallsOutsideTheStore(
      in: Scope(files: [
        SourceFile(
          path: "Sources/KeychainLive/KeychainStore.swift",
          source: "let s = SecItemAdd(query, nil)"
        ),
        SourceFile(
          path: "Sources/KeychainLive/Other.swift",
          source: """
            let s = SecItemDelete(query)
            let c = SecAccessControlCreateWithFlags(nil, a, f, &e)
            """
        ),
      ])
    )
    #expect(found.map(\.location.relativePath) == ["Sources/KeychainLive/Other.swift"])
  }

  @Test func unexplainedExposeSecretIsFound() {
    let found = Detect.unexplainedExposeSecret(
      in: scope(
        """
        let a = secret.exposeSecret()
        // Encoding for storage.
        let b = secret.exposeSecret()
        // exposeSecret: encoding to bytes for storage.
        let c = try key.encode(secret.exposeSecret())
        // exposeSecret: SecItemAdd takes the bytes.
        try await store.save(
          secret.exposeSecret(),
          key: key
        )
        let d = secret.exposeSecret()  // exposeSecret: hashing for the cache key.
        public func exposeSecret() -> Value { value }
        """
      )
    )
    #expect(found.map(\.location.line) == [1, 3])
  }

  @Test func secretConformancesAreFound() {
    let found = Detect.secretConformances(
      in: scope(
        """
        public struct Secret<Value: Sendable>: Sendable, Hashable {}
        extension Secret: Codable where Value: Codable {}
        extension Secret: Equatable where Value: Equatable {}
        extension Secret: CustomStringConvertible {}
        struct Other: Codable {}
        """
      )
    )
    #expect(found.map(\.location.line) == [1, 2])
  }

  @Test func errorPayloadsAreFound() {
    let found = Detect.errorPayloads(
      in: scope(
        """
        public enum KeychainError: Error {
          case itemNotFound
          case saveFailed(OSStatus)
          case decodingFailed(Data)
          case leaked(secret: Secret<Data>)
        }
        enum OtherError: Error { case wrapped(Data) }
        """
      )
    )
    #expect(found.map(\.location.line) == [4, 5])
  }

  @Test func loggingIsFound() {
    let found = Detect.logging(
      in: scope(
        """
        print("loaded")
        debugPrint(value)
        NSLog("saved")
        let logger = Logger(subsystem: "a", category: "b")
        dump(secret)
        formatter.print(issue)
        let text = "print() in a string is fine"
        """
      )
    )
    #expect(found.map(\.location.line).sorted() == [1, 2, 3, 4, 5])
  }

  @Test func publicRawAccountEndpointsAreFound() {
    let found = Detect.publicRawAccountEndpoints(
      in: scope(
        """
        public struct KeychainClient: Sendable {
          public var load: @Sendable (_ key: String, _ context: AuthContext?) async throws -> Secret<Data>
          package var delete: @Sendable (_ key: String) async throws -> Void
          public package(set) var keys: @Sendable () async throws -> [String]
        }
        public struct Other { public var load: @Sendable (_ key: String) -> Data }
        """
      )
    )
    #expect(found.map(\.name) == ["load"])
    #expect(found.map(\.location.line) == [2])
  }

  @Test func ungatedLiveSuitesAreFound() {
    let found = Detect.ungatedLiveSuites(
      in: scope(
        """
        #if os(macOS)
          @Suite struct A {}
          @Suite(.enabled(if: liveTestsEnabled)) struct B {
            @Suite struct Nested {}
          }
          @Suite(.enabled(if: liveTestsEnabled && SecureEnclave.isAvailable)) struct C {}
          @Suite(.enabled(if: SecureEnclave.isAvailable)) struct D {}
          struct Helper {}
        #endif
        """,
        at: "Tests/KeychainLiveTests/A.swift"
      )
    )
    #expect(found.map(\.name) == ["A", "D"])
  }

  @Test func sharedLiveServicesAreFound() {
    let found = Detect.sharedLiveServices(
      in: scope(
        """
        let a = KeychainClient.live(service: "tests", dataProtection: false)
        let b = KeychainClient.live(service: "swift-keychain.tests.\\(UUID().uuidString)")
        let c = SecureEnclaveClient.live(
          service: "swift-keychain.tests.\\(UUID().uuidString)",
          dataProtection: false
        )
        let d = SecureEnclaveClient.live(service: fixedService)
        let e = stream.live()
        """,
        at: "Tests/KeychainLiveTests/A.swift"
      )
    )
    #expect(found.map(\.location.line) == [1, 7])
  }
}
