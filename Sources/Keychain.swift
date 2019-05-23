//
//  Keychain.swift
//  Keychain
//
//  Created by Dmitry Nesterenko on 07/02/2018.
//  Copyright © 2018 Dmitry Nesterenko. All rights reserved.
//

import Foundation
import Security

public final class Keychain {
    
    enum Error: LocalizedError {
        
        case aclCreationFailed(error: Swift.Error?)
        case itemCopyFailed(status: OSStatus)
        case itemAddFailed(status: OSStatus)
        case itemUpdateFailed(status: OSStatus)
        case itemDeleteFailed(status: OSStatus)
        
        var errorDescription: String? {
            switch self {
            case .aclCreationFailed(let error):
                if let error = error {
                    return "Can't create acl object \(error)"
                } else {
                    return "Can't create acl object"
                }
            case .itemCopyFailed(let status):
                return localizedStatusDescription(status)
            case .itemAddFailed(let status):
                return localizedStatusDescription(status)
            case .itemUpdateFailed(let status):
                return localizedStatusDescription(status)
            case .itemDeleteFailed(let status):
                return localizedStatusDescription(status)
            }
        }
        
        private func localizedStatusDescription(_ status: OSStatus) -> String? {
            if #available(iOS 11.3, *) {
                return SecCopyErrorMessageString(status, nil) as String?
            } else {
                return nil
            }
        }
        
    }
    
    /// Access control object
    ///
    /// Access control object should be used as a value for kSecAttrAccessControl attribute in SecItemAdd,
    /// SecItemUpdate or SecKeyGeneratePair functions.  Accessing keychain items or performing operations on keys which are
    /// protected by access control objects can block the execution because of UI which can appear to satisfy the access control
    /// conditions, therefore it is recommended to either move those potentially blocking operations out of the main
    /// application thread or use combination of kSecUseAuthenticationContext and kSecUseAuthenticationUI attributes to control
    /// where the UI interaction can appear.
    public struct AccessControl {
        
        /// Predefined item attribute constants used to get or set values in a dictionary. The kSecAttrAccessible constant is the key and its value is one of the constants defined here. When asking SecItemCopyMatching to return the item's data, the error errSecInteractionNotAllowed will be returned if the item's data is not available until a device unlock occurs.
        public enum Accessibility: RawRepresentable {
            
            /// Item data can only be accessed
            /// while the device is unlocked. This is recommended for items that only
            /// need be accesible while the application is in the foreground.  Items
            /// with this attribute will migrate to a new device when using encrypted
            /// backups.
            case whenUnlocked
            
            /// Item data can only be
            /// accessed once the device has been unlocked after a restart.  This is
            /// recommended for items that need to be accesible by background
            /// applications. Items with this attribute will migrate to a new device
            /// when using encrypted backups.
            case afterFirstUnlock
            
            /// Item data can always be accessed
            /// regardless of the lock state of the device.  This is not recommended
            /// for anything except system use. Items with this attribute will migrate
            /// to a new device when using encrypted backups.
            case always
            
            /// Item data can
            /// only be accessed while the device is unlocked. This is recommended for
            /// items that only need to be accessible while the application is in the
            /// foreground and requires a passcode to be set on the device. Items with
            /// this attribute will never migrate to a new device, so after a backup
            /// is restored to a new device, these items will be missing. This
            /// attribute will not be available on devices without a passcode. Disabling
            /// the device passcode will cause all previously protected items to
            /// be deleted.
            case whenPasscodeSetThisDeviceOnly
            
            /// Item data can only
            /// be accessed while the device is unlocked. This is recommended for items
            /// that only need be accesible while the application is in the foreground.
            /// Items with this attribute will never migrate to a new device, so after
            /// a backup is restored to a new device, these items will be missing.
            case whenUnlockedThisDeviceOnly
            
            /// Item data can
            /// only be accessed once the device has been unlocked after a restart.
            /// This is recommended for items that need to be accessible by background
            /// applications. Items with this attribute will never migrate to a new
            /// device, so after a backup is restored to a new device these items will
            /// be missing.
            case afterFirstUnlockThisDeviceOnly
            
            /// Item data can always
            /// be accessed regardless of the lock state of the device.  This option
            /// is not recommended for anything except system use. Items with this
            /// attribute will never migrate to a new device, so after a backup is
            /// restored to a new device, these items will be missing.
            case alwaysThisDeviceOnly
            
            public init?(rawValue: CFString) {
                switch rawValue {
                case let value where value == kSecAttrAccessibleWhenUnlocked:
                    self = .whenUnlocked
                case let value where value == kSecAttrAccessibleAfterFirstUnlock:
                    self = .afterFirstUnlock
                case let value where value == kSecAttrAccessibleAlways:
                    self = .always
                case let value where value == kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly:
                    self = .whenPasscodeSetThisDeviceOnly
                case let value where value == kSecAttrAccessibleWhenUnlockedThisDeviceOnly:
                    self = .whenUnlockedThisDeviceOnly
                case let value where value == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly:
                    self = .afterFirstUnlockThisDeviceOnly
                case let value where value == kSecAttrAccessibleAlwaysThisDeviceOnly:
                    self = .alwaysThisDeviceOnly
                default:
                    return nil
                }
            }
            
            public var rawValue: CFString {
                switch self {
                case .whenUnlocked:
                    return kSecAttrAccessibleWhenUnlocked
                case .afterFirstUnlock:
                    return kSecAttrAccessibleAfterFirstUnlock
                case .always:
                    return kSecAttrAccessibleAlways
                case .whenPasscodeSetThisDeviceOnly:
                    return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
                case .whenUnlockedThisDeviceOnly:
                    return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                case .afterFirstUnlockThisDeviceOnly:
                    return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                case .alwaysThisDeviceOnly:
                    return kSecAttrAccessibleAlwaysThisDeviceOnly
                }
            }
            
        }
        
        public var protection: Accessibility
        public var flags: SecAccessControlCreateFlags?
        
        public init(protection: Accessibility, flags: SecAccessControlCreateFlags? = nil) {
            self.protection = protection
            self.flags = flags
        }
        
        public func create() throws -> SecAccessControl {
            var error: Unmanaged<CFError>?
            if let accessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, protection.rawValue, flags ?? [], &error) {
                return accessControl
            } else {
                let e = error?.takeRetainedValue() as Swift.Error?
                throw Error.aclCreationFailed(error: e)
            }
        }
        
    }
    
    /// Attribute Key Constants
    ///
    /// Predefined item attribute keys used to get or set values in a
    /// dictionary. Not all attributes apply to each item class. The table
    /// below lists the currently defined attributes for each item class:
    public struct Attributes {
        
        /// Class Value Constants
        ///
        /// Predefined item class constants used to get or set values in
        /// a dictionary. The kSecClass constant is the key and its value is one
        /// of the constants defined here. Note: on Mac OS X 10.6, only items
        /// of class kSecClassInternetPassword are supported.
        public enum ItemClass: RawRepresentable {
            
            /// The value that indicates an Internet password item.
            case internetPassword
            
            /// The value that indicates a generic password item.
            case genericPassword
            
            /// The value that indicates a certificate item.
            case certificate
            
            /// The value that indicates a cryptographic key item.
            case key
            
            /// Specifies identity items.
            ///
            /// An identity is a certificate paired with its associated private key. Because an identity is the combination of a private key and a certificate, this class shares attributes of both kSecClassKey and kSecClassCertificate.
            case identity
            
            public init?(rawValue: CFString) {
                switch rawValue {
                case let value where value == kSecClassInternetPassword:
                    self = .internetPassword
                case let value where value == kSecClassGenericPassword:
                    self = .genericPassword
                case let value where value == kSecClassCertificate:
                    self = .certificate
                case let value where value == kSecClassKey:
                    self = .key
                case let value where value == kSecClassIdentity:
                    self = .identity
                default:
                    return nil
                }
            }
            
            public var rawValue: CFString {
                switch self {
                case .internetPassword:
                    return kSecClassInternetPassword
                case .genericPassword:
                    return kSecClassGenericPassword
                case .certificate:
                    return kSecClassCertificate
                case .key:
                    return kSecClassKey
                case .identity:
                    return kSecClassIdentity
                }
            }
            
        }
        
        /// kSecUseAuthenticationUI Value Constants
        ///
        /// Predefined item attribute constants used to get or set values
        /// in a dictionary. The kSecUseAuthenticationUI constant is the key and its
        /// value is one of the constants defined here.
        /// If the key kSecUseAuthenticationUI not provided then kSecUseAuthenticationUIAllow
        /// is used as default.
        public enum UIAuthentication: RawRepresentable {
            
            /// Specifies that authenticate UI can appear.
            case allow
            
            /// Specifies that the error
            /// errSecInteractionNotAllowed will be returned if an item needs
            /// to authenticate with UI
            case fail
            
            /// Specifies that all items which need
            /// to authenticate with UI will be silently skipped. This value can be used
            /// only with SecItemCopyMatching.
            case skip
            
            public init?(rawValue: CFString) {
                switch rawValue {
                case let value where value == kSecUseAuthenticationUIAllow:
                    self = .allow
                case let value where value == kSecUseAuthenticationUIFail:
                    self = .fail
                case let value where value == kSecUseAuthenticationUISkip:
                    self = .skip
                default:
                    return nil
                }
            }
            
            public var rawValue: CFString {
                switch self {
                case .allow:
                    return kSecUseAuthenticationUIAllow
                case .fail:
                    return kSecUseAuthenticationUIFail
                case .skip:
                    return kSecUseAuthenticationUISkip
                }
            }
            
        }
        
        public enum MatchLimit: RawRepresentable {
            
            case one
            case all
            case count(NSNumber)
            
            public init?(rawValue: Any) {
                switch rawValue {
                case let value as String where value == kSecMatchLimitOne as String:
                    self = .one
                case let value as String where value == kSecMatchLimitAll as String:
                    self = .all
                case let value as NSNumber:
                    self = .count(value)
                default:
                    return nil
                }
            }
            
            public var rawValue: Any {
                switch self {
                case .one:
                    return kSecMatchLimitOne
                case .all:
                    return kSecMatchLimitAll
                case .count(let count):
                    return count as NSNumber
                }
            }
            
        }
        
        private(set) var storage = [String: Any]()
        
        /// Returns a value that indicates an internet password item.
        ///
        /// - Parameters:
        ///     - account: Item's account name.
        public static func internetPasswordItem(account: String) -> Attributes {
            return Attributes {
                $0.itemClass = .internetPassword
                $0.account = account
            }
        }
        
        /// Returns a value that indicates a generic password item.
        ///
        /// - Parameters:
        ///     - account: Item's account name.
        ///     - generic: Item's user-defined attributes.
        public static func genericPasswordItem(account: String, generic: Data? = nil) -> Attributes {
            return Attributes {
                $0.itemClass = .genericPassword
                $0.account = account
                $0.generic = generic
            }
        }
        
        /// A key whose value is a string indicating the access group an item is in.
        public var accessGroup: String? {
            get {
                return storage[kSecAttrAccessGroup as String] as? String
            }
            set {
                storage[kSecAttrAccessGroup as String] = newValue
            }
        }
        
        /// Dictionary key whose value is the item's class code.
        public var itemClass: ItemClass? {
            get {
                guard let value = storage[kSecClass as String] as? String else {
                    return nil
                }
                return ItemClass(rawValue: value as CFString)
            }
            set {
                storage[kSecClass as String] = newValue?.rawValue
            }
        }
        
        /// Service attribute key.
        ///
        /// The corresponding value is a string of type CFStringRef that represents the service associated with this item. Items of class kSecClassGenericPassword have this attribute.
        public var service: String? {
            get {
                return storage[kSecAttrService as String] as? String
            }
            set {
                storage[kSecAttrService as String] = newValue
            }
        }
        
        /// Account attribute key.
        ///
        /// The corresponding value is of type CFStringRef and contains an account name. Items of class kSecClassGenericPassword and kSecClassInternetPassword have this attribute.
        public var account: String? {
            get {
                return storage[kSecAttrAccount as String] as? String
            }
            set {
                storage[kSecAttrAccount as String] = newValue
            }
        }
        
        /// A key whose value indicates the item's user-defined attributes.
        ///
        /// The corresponding value is of type CFData and contains a user-defined attribute. Items of class kSecClassGenericPassword have this attribute.
        public var generic: Data? {
            get {
                return storage[kSecAttrGeneric as String] as? Data
            }
            set {
                storage[kSecAttrGeneric as String] = newValue
            }
        }
        
        /// Data attribute key. A persistent reference to a credential can be stored on disk for later use or passed to other processes.
        ///
        /// The corresponding value is of type CFDataRef.  For keys and password items, the data is secret (encrypted) and may require the user to enter a password for access.
        public var valueData: Data? {
            get {
                return storage[kSecValueData as String] as? Data
            }
            set {
                storage[kSecValueData as String] = newValue
            }
        }
        
        /// UI authentication key.
        ///
        /// The corresponding value is of type CFStringRef and contains one of the values listed in UI Authentication Values. The value specifies whether or not the user may be prompted for authentication, if needed. A default value of kSecUseAuthenticationUIAllow is assumed when this key is not present.
        public var useAuthenticationUi: UIAuthentication? {
            get {
                guard let value = storage[kSecUseAuthenticationUI as String] as? String else {
                    return nil
                }
                
                return UIAuthentication(rawValue: value as CFString)
            }
            set {
                storage[kSecUseAuthenticationUI as String] = newValue?.rawValue
            }
        }
        
        /// Access control key.
        ///
        /// The corresponding value is a SecAccessControlRef object, created with the SecAccessControlCreateWithFlags function, containing access control conditions for the item.
        /// - Important:
        ///   This attribute is mutually exclusive with the kSecAttrAccess attribute.
        public var accessControl: SecAccessControl? {
            get {
                guard let value = storage[kSecAttrAccessControl as String] else {
                    return nil
                }
                return (value as! SecAccessControl) // swiftlint:disable:this force_cast
            }
            set {
                storage[kSecAttrAccessControl as String] = newValue
            }
        }
        
        /// Operation prompt key.
        ///
        /// The corresponding value is of type CFStringRef and represents a string describing the operation for which the app is attempting to authenticate. When performing user authentication, the system includes the string in the user prompt. The app is responsible for text localization.
        public var useOperationPrompt: String? {
            get {
                return storage[kSecUseOperationPrompt as String] as? String
            }
            set {
                storage[kSecUseOperationPrompt as String] = newValue
            }
        }
        
        /// Return data attribute key.
        ///
        /// The corresponding value is of type CFBooleanRef. A value of kCFBooleanTrue indicates that the data of an item should be returned in the form of a CFDataRef. For keys and password items, data is secret (encrypted) and may require the user to enter a password for access
        public var returnData: Bool? {
            get {
                return storage[kSecReturnData as String] as? Bool
            }
            set {
                storage[kSecReturnData as String] = newValue
            }
        }
        
        /// Return attributes attribute key.
        ///
        /// The corresponding value is of type CFBooleanRef. A value of kCFBooleanTrue indicates that a dictionary of the (unencrypted) attributes of an item should be returned in the form of a CFDictionaryRef.
        public var returnAttributes: Bool? {
            get {
                return storage[kSecReturnAttributes as String] as? Bool
            }
            set {
                storage[kSecReturnAttributes as String] = newValue
            }
        }
        
        /// Match limit attribute key.
        ///
        /// The corresponding value is of type CFNumberRef. If provided, this value specifies the maximum number of results to return or otherwise act upon. For a single item, specify kSecMatchLimitOne. To specify all matching items, specify kSecMatchLimitAll. The default behavior is function-dependent.
        public var matchLimit: MatchLimit? {
            get {
                guard let value = storage[kSecMatchLimit as String] else {
                    return nil
                }
                
                return MatchLimit(rawValue: value)
            }
            set {
                storage[kSecMatchLimit as String] = newValue?.rawValue
            }
        }
        
        fileprivate init(storage: [String: Any] = [:]) {
            self.storage = storage
        }
        
        public init(_ builder: (inout Attributes) -> Void) {
            self.init()
            builder(&self)
        }
        
    }
    
    public let service: String
    public let accessGroup: String?
    
    public init(service: String, accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }
    
    public func data(query: Attributes) throws -> Data {
        var mutableQuery = query
        mutableQuery.service = service
        mutableQuery.accessGroup = accessGroup
        mutableQuery.returnData = true
        mutableQuery.returnAttributes = true
        mutableQuery.matchLimit = .one
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(mutableQuery.storage as CFDictionary, &result)
        if let result = result as? [String: Any] {
            let attributes = Attributes(storage: result)
            if let data = attributes.valueData {
                return data
            }
        }
        throw Error.itemCopyFailed(status: status)
    }
    
    public func setData(_ data: Data, query: Attributes, accessControl: AccessControl? = nil) throws {
        var mutableQuery = query
        mutableQuery.useAuthenticationUi = .fail
        
        do {
            _ = try self.data(query: mutableQuery)
            try updateData(data, query: query, accessControl: accessControl)
        } catch Error.itemCopyFailed(let status) where status == errSecInteractionNotAllowed {
            // rewrite
            try deleteData(query: query)
            try addData(data, query: query, accessControl: accessControl)
        } catch Error.itemCopyFailed(let status) where status == errSecItemNotFound {
            // add
            try addData(data, query: query, accessControl: accessControl)
        }
    }
    
    private func addData(_ data: Data, query: Attributes, accessControl: AccessControl? = nil) throws {
        var mutableQuery = query
        mutableQuery.service = service
        mutableQuery.accessGroup = accessGroup
        mutableQuery.valueData = data
        mutableQuery.accessControl = try accessControl?.create()
        
        let status = SecItemAdd(mutableQuery.storage as CFDictionary, nil)
        if status != errSecSuccess {
            throw Error.itemAddFailed(status: status)
        }
    }
    
    private func updateData(_ data: Data, query: Attributes, accessControl: AccessControl? = nil) throws {
        var mutableQuery = query
        mutableQuery.service = service
        mutableQuery.accessGroup = accessGroup
        
        var update = Attributes()
        update.valueData = data
        update.accessControl = try accessControl?.create()
        
        let status = SecItemUpdate(mutableQuery.storage as CFDictionary, update.storage as CFDictionary)
        if status != errSecSuccess {
            throw Error.itemUpdateFailed(status: status)
        }
    }
    
    public func deleteData(query: Attributes) throws {
        var mutableQuery = query
        mutableQuery.service = service
        mutableQuery.accessGroup = accessGroup
        
        let status = SecItemDelete(mutableQuery.storage as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw Error.itemDeleteFailed(status: status)
        }
    }
    
    /// Disables authentication UI.
    public func hasData(query: Attributes) throws -> Bool {
        var mutableQuery = query
        mutableQuery.useAuthenticationUi = .fail
        
        do {
            _ = try self.data(query: mutableQuery)
        } catch Error.itemCopyFailed(let status) where status == errSecItemNotFound {
            return false
        } catch Error.itemCopyFailed(let status) where status == errSecInteractionNotAllowed {
            return true
        }
        
        return true
    }
    
}
