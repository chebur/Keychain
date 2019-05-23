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
        
        try XCTContext.runActivity(named: "Should set new data") { _ in
            let data = "secret".data(using: .utf8)!
            XCTAssertNoThrow(try keychain.setData(data, query: query))
        }
        
        try XCTContext.runActivity(named: "Should update existing data") { _ in
            let data = "update".data(using: .utf8)!
            XCTAssertNoThrow(try keychain.setData(data, query: query))
        }
    }
    
    func testDataDeleting() throws {
        let keychain = Keychain(service: UUID().uuidString)
        
        try XCTContext.runActivity(named: "Should delete existing data") { _ in
            let query = Keychain.Attributes.genericPasswordItem(account: "account")
            let original = "secret".data(using: .utf8)!
            try keychain.setData(original, query: query)
            XCTAssertNoThrow(try keychain.deleteData(query: query))
            XCTAssertThrowsError(try keychain.data(query: query))
        }
        
        try XCTContext.runActivity(named: "Should delete missing data") { _ in
            let query = Keychain.Attributes.genericPasswordItem(account: "not found")
            XCTAssertNoThrow(try keychain.deleteData(query: query))
            XCTAssertThrowsError(try keychain.data(query: query))
        }
        
        try XCTContext.runActivity(named: "Should delete all data") { _ in
            try keychain.setData("1".data(using: .utf8)!, query: .genericPasswordItem(account: "1"))
            try keychain.setData("2".data(using: .utf8)!, query: .genericPasswordItem(account: "2"))
            try keychain.setData("3".data(using: .utf8)!, query: .genericPasswordItem(account: "3"))
            
            let query = Keychain.Attributes {
                $0.itemClass = .genericPassword
            }
            try? keychain.deleteData(query: query)
            XCTAssertThrowsError(try keychain.data(query: .genericPasswordItem(account: "1")))
            XCTAssertThrowsError(try keychain.data(query: .genericPasswordItem(account: "2")))
            XCTAssertThrowsError(try keychain.data(query: .genericPasswordItem(account: "3")))
        }
    }
    
    func testDataExistenceTesting() throws {
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
        
        try XCTContext.runActivity(named: "Should throw when fetch missing data") { _ in
            let query = Keychain.Attributes.genericPasswordItem(account: "not found")
            XCTAssertThrowsError(try keychain.data(query: query))
        }
    }
    
    func testAccessControl() throws {
        let keychain = Keychain(service: UUID().uuidString)
        
        try XCTContext.runActivity(named: "Should succeesfully use `always` protection") { _ in
            let query = Keychain.Attributes.genericPasswordItem(account: "account")
            let accessControl = Keychain.AccessControl(protection: .always)
            let data = "secret".data(using: .utf8)!
            XCTAssertNoThrow(try keychain.setData(data, query: query, accessControl: accessControl))
            XCTAssertNoThrow(try keychain.data(query: query))
        }
    }
    
}
