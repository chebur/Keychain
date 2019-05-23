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
        let query = Keychain.Attributes.genericPasswordItem(account: "account")
        
        try XCTContext.runActivity(named: "Should successfully set new data") { _ in
            let data = "secret".data(using: .utf8)!
            XCTAssertNoThrow(try keychain.setData(data, query: query))
        }
        
        try XCTContext.runActivity(named: "Should successfully update existing data") { _ in
            let data = "update".data(using: .utf8)!
            XCTAssertNoThrow(try keychain.setData(data, query: query))
        }
    }
    
    func testDataDeleting() throws {
        let keychain = Keychain(service: UUID().uuidString)
        
        try XCTContext.runActivity(named: "Should successfully delete existing data") { _ in
            let query = Keychain.Attributes.genericPasswordItem(account: "account")
            let original = "secret".data(using: .utf8)!
            try keychain.setData(original, query: query)
            XCTAssertNoThrow(try keychain.deleteData(query: query))
        }
        
        try XCTContext.runActivity(named: "Should successfully delete missing data") { _ in
            let query = Keychain.Attributes.genericPasswordItem(account: "not found")
            XCTAssertNoThrow(try keychain.deleteData(query: query))
        }
    }
    
    func testDataExistanceTesting() throws {
        let keychain = Keychain(service: UUID().uuidString)
        
        try XCTContext.runActivity(named: "Should return true for existing data") { _ in
            let query = Keychain.Attributes.genericPasswordItem(account: "account")
            let data = "secret".data(using: .utf8)!
            try keychain.setData(data, query: query)
            let isDataExists = try keychain.hasData(query: query)
            XCTAssertTrue(isDataExists)
        }
        
        try XCTContext.runActivity(named: "Should return false for missing data") { _ in
            let query = Keychain.Attributes.genericPasswordItem(account: "not found")
            let isDataExists = try keychain.hasData(query: query)
            XCTAssertFalse(isDataExists)
        }
    }
    
    func testDataFetching() throws {
        let keychain = Keychain(service: UUID().uuidString)
        
        try XCTContext.runActivity(named: "Should return existing data") { _ in
            let query = Keychain.Attributes.genericPasswordItem(account: "account")
            let data = "secret".data(using: .utf8)!
            try keychain.setData(data, query: query)
            XCTAssertEqual(try keychain.data(query: query), data)
        }
        
        try XCTContext.runActivity(named: "Should throw when trying to fetch missing data") { _ in
            let query = Keychain.Attributes.genericPasswordItem(account: "not found")
            XCTAssertThrowsError(try keychain.data(query: query))
        }
    }
    
    func testAccessControl() throws {
        let keychain = Keychain(service: UUID().uuidString)
        
        try XCTContext.runActivity(named: "Should succeed using default `always` protection") { _ in
            let query = Keychain.Attributes.genericPasswordItem(account: "account")
            let accessControl = Keychain.AccessControl(protection: .always)
            let data = "secret".data(using: .utf8)!
            XCTAssertNoThrow(try keychain.setData(data, query: query, accessControl: accessControl))
            XCTAssertNoThrow(try keychain.data(query: query))
        }
    }
    
}
