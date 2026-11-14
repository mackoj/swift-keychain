import LLMCheck
import SwiftSyntax

/// The detectors, separate from the codebase so `DetectorTests` can run them on snippets.
enum Detect {
  /// `import Security`, anywhere in the scope.
  static func securityImports(in scope: Scope) -> [Match<ImportDeclSyntax>] {
    scope.imports(of: "Security")
  }

  /// Top-level statements outside an `#if` whose first condition includes `canImport(Security)`.
  static func unguardedLiveCode(in scope: Scope) -> [Match<Syntax>] {
    scope.files.flatMap { file in
      file.syntax.statements.filter { statement in
        guard let ifConfig = statement.item.as(IfConfigDeclSyntax.self),
          let condition = ifConfig.clauses.first?.condition?.trimmedDescription
        else { return true }
        return !condition.contains("canImport(Security)")
      }
      .map { Match(node: Syntax($0), file: file) }
    }
  }

  /// Calls to `SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate` and `SecItemDelete` outside
  /// `KeychainStore.swift`.
  static func secItemCallsOutsideTheStore(in scope: Scope) -> [Match<FunctionCallExprSyntax>] {
    scope.excluding("KeychainStore.swift")
      .calls(named: "SecItemAdd", "SecItemCopyMatching", "SecItemUpdate", "SecItemDelete")
  }

  /// `x.exposeSecret()` whose statement has no `// exposeSecret:` comment, above it or at the end
  /// of its last line.
  static func unexplainedExposeSecret(in scope: Scope) -> [Match<FunctionCallExprSyntax>] {
    scope.calls(named: "exposeSecret").filter { call in
      guard call.node.receiver != nil else { return false }
      let statement = sequence(first: Syntax(call.node), next: \.parent).first {
        $0.is(CodeBlockItemSyntax.self)
      }
      let comments = statement?.attachedComments ?? []
      return !comments.contains { $0.hasPrefix("// exposeSecret:") }
    }
  }

  /// What `Secret` must never conform to (D-9).
  static let forbiddenSecretConformances = ["Codable", "Encodable", "Decodable", "Hashable"]

  /// `Secret`'s declaration and extensions that add a forbidden conformance.
  static func secretConformances(in scope: Scope) -> [Declaration] {
    (scope.structs + scope.extensions).named("Secret").filter { declaration in
      forbiddenSecretConformances.contains { declaration.inherits(from: $0) }
    }
  }

  /// What a `KeychainError` case may carry.
  static let allowedErrorPayloads: Set<String> = ["OSStatus"]

  /// Associated values of `KeychainError` cases whose type is not an `OSStatus`.
  static func errorPayloads(in scope: Scope) -> [Match<EnumCaseParameterSyntax>] {
    scope.containing("enum KeychainError").nodes(of: EnumCaseParameterSyntax.self) { match in
      let enclosingEnum = sequence(first: Syntax(match.node), next: \.parent).lazy
        .compactMap { $0.as(EnumDeclSyntax.self) }.first
      return enclosingEnum?.name.text == "KeychainError"
        && !allowedErrorPayloads.contains(match.node.type.trimmedDescription)
    }
  }

  /// `print`, `debugPrint`, `dump`, `NSLog` and `os_log` calls, and any `Logger`.
  static func logging(in scope: Scope) -> [Match<Syntax>] {
    let calls = scope.calls(named: "print", "debugPrint", "dump", "NSLog", "os_log").filter {
      $0.node.receiver == nil
    }
    return scope.references(to: "Logger") + calls.map(\.erased)
  }

  /// `public` properties of `KeychainClient` whose closure takes a `key: String`.
  static func publicRawAccountEndpoints(in scope: Scope) -> [Declaration] {
    scope.structs.named("KeychainClient").flatMap(\.variables).filter { variable in
      variable.hasModifier("public")
        && variable.syntax.trimmedDescription.contains("_ key: String")
    }
  }

  /// `@unchecked Sendable` conformances whose declaration has no `//` comment. Doc comments
  /// describe the type to users; they don't count.
  static func uncommentedUncheckedSendable(in scope: Scope) -> [Match<AttributeSyntax>] {
    scope.containing("@unchecked").nodes(of: AttributeSyntax.self) { match in
      guard match.node.attributeName.trimmedDescription == "unchecked" else { return false }
      let declaration = sequence(first: Syntax(match.node), next: \.parent).first {
        $0.is(DeclSyntax.self)
      }
      let comments = declaration.map(commentsOnDeclarationLine) ?? []
      return !comments.contains { $0.hasPrefix("//") && !$0.hasPrefix("///") }
    }
  }

  /// The declaration's leading comments, and one at the end of the line its body opens on.
  private static func commentsOnDeclarationLine(_ declaration: Syntax) -> [String] {
    let leading = declaration.leadingComments
    let brace = declaration.tokens(viewMode: .sourceAccurate).first {
      $0.tokenKind == .leftBrace
    }
    return leading + (brace?.trailingComments ?? [])
  }

  /// `import XCTest`.
  static func xcTestImports(in scope: Scope) -> [Match<ImportDeclSyntax>] {
    scope.imports(of: "XCTest")
  }

  /// The `.disabled(…)` trait, wherever a test or suite takes it.
  static func disabledTests(in scope: Scope) -> [Match<FunctionCallExprSyntax>] {
    scope.calls(named: "disabled").filter { call in
      call.node.receiver == nil && call.node.calledExpression.is(MemberAccessExprSyntax.self)
    }
  }

  /// Top-level `@Suite` types whose attribute doesn't gate them on `liveTestsEnabled`.
  static func ungatedLiveSuites(in scope: Scope) -> [Declaration] {
    scope.topLevelDeclarations.filter { $0.hasAttribute("Suite") }.filter { suite in
      let attributes = suite.syntax.asProtocol(WithAttributesSyntax.self)?.attributes
      return !(attributes?.trimmedDescription.contains(".enabled(if: liveTestsEnabled") ?? false)
    }
  }

  /// `.live(service: …)` calls whose service is not made with a fresh `UUID()`.
  static func sharedLiveServices(in scope: Scope) -> [Match<FunctionCallExprSyntax>] {
    scope.calls(named: "live").filter { call in
      guard let service = call.node.argument(labeled: "service") else { return false }
      return !service.expression.trimmedDescription.contains("UUID()")
    }
  }
}
