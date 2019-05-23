# Keychain
Keychain helper utility class

## Usage
See [KeychainTests.swift](Sources/KeychainTests.swift) for usage examples.

```swift
func testDataSetting() throws {
    let keychain = Keychain(service: UUID().uuidString)
    let query = Keychain.Attributes.genericPasswordItem(account: "account")
    let accessControl = Keychain.AccessControl(protection: .always, flags: .userPresence)
    let data = "secret".data(using: .utf8)!
    
    try keychain.setData(original, query: data, accessControl: accessControl)
    XCTAssertEqual(try keychain.data(query: query), data)
}
```
