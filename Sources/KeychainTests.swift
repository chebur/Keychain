//
//  KeychainTests.swift
//  Keychain
//
//  Created by Dmitry Nesterenko on 07/02/2017.
//  Copyright © 2017 Dmitry Nesterenko. All rights reserved.
//

import XCTest
import Keychain

class KeychainTests: XCTestCase {

    func testDataSetting() throws {
        let keychain = Keychain(service: UUID().uuidString)
        let attributes = Keychain.Attributes.genericPasswordItem(forAccount: "account", generic: nil)
        let acl = Keychain.AccessControl(protection: .always)
        let original = "secret".data(using: .utf8)!
        
        try keychain.setData(original, attributes: attributes, acl: acl)
        let restored = try keychain.data(attributes: attributes)
        XCTAssertEqual(restored, original)
    }

    func testDataUpdating() throws {
        let keychain = Keychain(service: UUID().uuidString)
        let attributes = Keychain.Attributes.genericPasswordItem(forAccount: "account", generic: nil)
        let acl = Keychain.AccessControl(protection: .always)
        
        try XCTContext.runActivity(named: "Set initial data for given key") { activity in
            let original = "secret1".data(using: .utf8)!
            try keychain.setData(original, attributes: attributes, acl: acl)
            let restored = try keychain.data(attributes: attributes)
            XCTAssertEqual(restored, original)
        }
        
        try XCTContext.runActivity(named: "Update stored value with new data") { activity in
            let original = "secret2".data(using: .utf8)!
            try keychain.setData(original, attributes: attributes, acl: acl)
            let restored = try keychain.data(attributes: attributes)
            XCTAssertEqual(restored, original)
        }
    }
    
    func testDataDeleting() throws {
        let keychain = Keychain(service: UUID().uuidString)
        let attributes = Keychain.Attributes.genericPasswordItem(forAccount: "account", generic: nil)
        let acl = Keychain.AccessControl(protection: .always)
        
        try XCTContext.runActivity(named: "Set initial data for given key") { activity in
            let original = "secret".data(using: .utf8)!
            try keychain.setData(original, attributes: attributes, acl: acl)
        }
        
        try XCTContext.runActivity(named: "Delete stored data") { activity in
            try keychain.deleteData(attributes: attributes)
        }
    }
    
    func testDataExists() throws {
        let keychain = Keychain(service: UUID().uuidString)
        let attributes = Keychain.Attributes.genericPasswordItem(forAccount: "account", generic: nil)
        let acl = Keychain.AccessControl(protection: .always)
        
        let data = "secret".data(using: .utf8)!
        try keychain.setData(data, attributes: attributes, acl: acl)
        let isDataExists = try keychain.isDataExists(attributes: attributes)
        XCTAssertTrue(isDataExists)
    }
    
}
