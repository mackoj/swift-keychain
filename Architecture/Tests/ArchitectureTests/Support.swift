import LLMCheck

/// The swift-keychain repository, rooted where `.llm-check.yaml` is. Its file list and every parsed
/// file are shared by all suites, which Swift Testing runs in parallel.
func keychain() throws -> Codebase { try Codebase() }

extension RuleCategory {
  static let modules = RuleCategory(
    "modules",
    description: """
      The interface / live split. Read before you add an `import` or a `SecItem` call to `Sources`.
      """
  )
  static let secrets = RuleCategory(
    "secrets",
    description: """
      Where secret bytes may go. Read before you call `exposeSecret()`, add an error case or log.
      """
  )
  static let api = RuleCategory(
    "api",
    description: "The public surface. Read before you make a client endpoint or a type public."
  )
  static let testing = RuleCategory(
    "testing",
    description: "Swift Testing and the live keychain. Read before you add or skip a test."
  )
}
