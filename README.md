# Keychain
Keychain helper utility class

## Usage

```swift
func testDataSetting() throws {
    let keychain = Keychain(service: UUID().uuidString)
    let attributes = Keychain.Attributes.genericPasswordItem(forAccount: "account", generic: nil)
    let acl = Keychain.AccessControl(protection: .always)
    let original = "secret".data(using: .utf8)!
    
    try keychain.setData(original, attributes: attributes, acl: acl)
    let restored = try keychain.data(attributes: attributes)
    XCTAssertEqual(restored, original)
}
```
