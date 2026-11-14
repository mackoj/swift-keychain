import LLMCheck
import Testing

/// The rules, run on the repository. A failure prints the rule, why it exists and how to fix it.
@Suite("Architecture rules")
struct ArchitectureRules {
  static func sources() throws -> Scope { try keychain().productionCode.in("/Sources") }
  static func tests() throws -> Scope { try keychain().testCode.in("/Tests") }

  @Test func interfaceNeverImportsSecurity() throws {
    let interface = try Self.sources().in("Sources/Keychain")
    #expect(interface.relativePaths.count > 10)
    expectNone(Detect.securityImports(in: interface), rule: .interfaceNeverImportsSecurity)
  }

  @Test func liveCodeIsGuarded() throws {
    let live = try Self.sources().in("Sources/KeychainLive")
    #expect(live.relativePaths.count >= 3)
    expectNone(Detect.unguardedLiveCode(in: live), rule: .liveCodeIsGuarded)
  }

  @Test func secItemCallsStayInTheStore() throws {
    let sources = try Self.sources()
    #expect(sources.calls(named: "SecItemAdd").count > 0)
    expectNone(Detect.secItemCallsOutsideTheStore(in: sources), rule: .secItemCallsStayInTheStore)
  }

  @Test func exposeSecretSaysWhy() throws {
    let sources = try Self.sources()
    #expect(sources.calls(named: "exposeSecret").count >= 4)
    expectNone(Detect.unexplainedExposeSecret(in: sources), rule: .exposeSecretSaysWhy)
  }

  @Test func secretIsNeitherCodableNorHashable() throws {
    let sources = try Self.sources()
    #expect(sources.structs.named("Secret").count == 1)
    expectNone(Detect.secretConformances(in: sources), rule: .secretIsNeitherCodableNorHashable)
  }

  @Test func errorsCarryNoBytes() throws {
    let sources = try Self.sources()
    #expect(sources.enums.named("KeychainError").count == 1)
    expectNone(Detect.errorPayloads(in: sources), rule: .errorsCarryNoBytes)
  }

  @Test func libraryNeverLogs() throws {
    expectNone(Detect.logging(in: try Self.sources()), rule: .libraryNeverLogs)
  }

  @Test func rawAccountEndpointsArePackage() throws {
    let sources = try Self.sources()
    #expect(sources.structs.named("KeychainClient").flatMap(\.variables).count > 5)
    expectNone(
      Detect.publicRawAccountEndpoints(in: sources),
      rule: .rawAccountEndpointsArePackage
    )
  }

  @Test func uncheckedSendableExplainsItself() throws {
    expectNone(
      Detect.uncommentedUncheckedSendable(in: try Self.sources()),
      rule: .uncheckedSendableExplainsItself
    )
  }

  @Test func testsUseSwiftTesting() throws {
    let tests = try Self.tests()
    #expect(tests.containing("import Testing").relativePaths.count >= 4)
    expectNone(Detect.xcTestImports(in: tests), rule: .testsUseSwiftTesting)
  }

  @Test func testsAreNotDisabled() throws {
    expectNone(Detect.disabledTests(in: try Self.tests()), rule: .testsAreNotDisabled)
  }

  @Test func liveSuitesCanBeSkipped() throws {
    let live = try Self.tests().in("Tests/KeychainLiveTests")
    #expect(live.topLevelDeclarations.filter { $0.hasAttribute("Suite") }.count >= 2)
    expectNone(Detect.ungatedLiveSuites(in: live), rule: .liveSuitesCanBeSkipped)
  }

  @Test func liveTestsUseAFreshService() throws {
    let tests = try Self.tests()
    #expect(tests.calls(named: "live").count >= 2)
    expectNone(Detect.sharedLiveServices(in: tests), rule: .liveTestsUseAFreshService)
  }
}

/// Keeps `docs/architecture-rules.md` in step with the rules. Regenerate with
/// `LLM_CHECK_RECORD=1 xcrun swift test --package-path Architecture`.
@Test func rulesDocumentIsUpToDate() throws {
  let catalog = RuleCatalog(allRules)
  #expect(catalog.duplicateIDs.isEmpty)
  try expectFile(
    "docs/architecture-rules.md",
    in: keychain(),
    matches: catalog.markdown(
      title: "Architecture rules",
      introduction: """
        The mechanical part of `CLAUDE.md` ("Layout", "Rules") and `docs/DECISIONS.md`, enforced \
        by the `Architecture/` package with \
        [swift-llm-check](https://github.com/mackoj/swift-llm-check): \
        `xcrun swift test --package-path Architecture` (macOS). Generated from its rules; do not \
        edit by hand.
        """
    )
  )
}
