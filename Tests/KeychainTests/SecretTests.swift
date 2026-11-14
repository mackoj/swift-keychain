import Foundation
import Keychain
import Testing

struct SecretTests {
  @Test func descriptionAndDumpAreRedacted() {
    let secret = Secret("hunter2")
    var dumped = ""
    dump(secret, to: &dumped)

    #expect("\(secret)" == "Secret<String>(redacted)")
    #expect(String(reflecting: secret) == "Secret<String>(redacted)")
    #expect(!dumped.contains("hunter2"))
  }

  @Test func equalityComparesValues() {
    #expect(Secret("a") == Secret("a"))
    #expect(Secret("a") != Secret("b"))
    #expect(Secret(Data([1, 2])) == Secret(Data([1, 2])))
    #expect(Secret(Data([1, 2])) != Secret(Data([1, 2, 3])))
    #expect(Secret(42) == Secret(42))
  }

  @Test func equalityComparesUTF8AndSlices() {
    let bridged = NSString(string: "café ✓").description

    #expect(Secret("café ✓") == Secret(bridged))
    #expect(Secret("café") != Secret("cafe"))
    #expect(Secret("ab") != Secret("abc"))
    #expect(Secret(Data([0, 1, 2])[1...]) == Secret(Data([1, 2])))
  }

  @Test func mapKeepsTheValueWrapped() {
    let length = Secret("hunter2").map(\.count)
    #expect(length == Secret(7))
  }
}
