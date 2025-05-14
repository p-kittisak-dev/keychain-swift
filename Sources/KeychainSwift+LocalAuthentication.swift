//
//  KeychainSwift+LocalAuthentication.swift
//  KeychainSwift
//
//  Created by Kittisak Phetrungnapha on 14/5/2568 BE.
//  Copyright © 2568 BE Evgenii Neumerzhitckii. All rights reserved.
//

import LocalAuthentication

extension KeychainSwift {
  
  @discardableResult
  public func secureSet(_ value: Data, forKey key: String, context: LAContext? = nil) -> Bool {
    
    // The lock prevents the code to be run simultaneously
    // from multiple threads which may result in crashing
    lock.lock()
    defer { lock.unlock() }
    
    deleteNoLock(key) // Delete any existing key before saving it
      
    let prefixedKey = keyWithPrefix(key)
      
    let accessControl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .userPresence, nil)
    
    var query: [String : Any] = [
      KeychainSwiftConstants.klass       : kSecClassGenericPassword,
      KeychainSwiftConstants.attrAccount : prefixedKey,
      KeychainSwiftConstants.valueData   : value,
      KeychainSwiftConstants.accessControl  : accessControl as Any
    ]
    if let context {
      query[KeychainSwiftConstants.authenticationContext] = context
    }
      
    query = addAccessGroupWhenPresent(query)
    query = addSynchronizableIfRequired(query, addingItems: true)
    lastQueryParameters = query
    
    lastResultCode = SecItemAdd(query as CFDictionary, nil)
    
    return lastResultCode == noErr
  }
  
  @discardableResult
  public func secureSet(_ value: String, forKey key: String, context: LAContext? = nil) -> Bool {
    if let value = value.data(using: String.Encoding.utf8) {
      return secureSet(value, forKey: key, context: context)
    }
    return false
  }
  
  @discardableResult
  public func secureSet(_ value: Bool, forKey key: String, context: LAContext? = nil) -> Bool {
    let bytes: [UInt8] = value ? [1] : [0]
    let data = Data(bytes)
    return secureSet(data, forKey: key, context: context)
  }
  
  public func secureGetData(_ key: String, asReference: Bool = false, context: LAContext? = nil) -> Data? {
    // The lock prevents the code to be run simultaneously
    // from multiple threads which may result in crashing
    lock.lock()
    defer { lock.unlock() }
    
    let prefixedKey = keyWithPrefix(key)
    
    var query: [String: Any] = [
      KeychainSwiftConstants.klass       : kSecClassGenericPassword,
      KeychainSwiftConstants.attrAccount : prefixedKey,
      KeychainSwiftConstants.matchLimit  : kSecMatchLimitOne
    ]
    if let context {
      query[KeychainSwiftConstants.authenticationContext] = context
    }
    
    if asReference {
      query[KeychainSwiftConstants.returnReference] = kCFBooleanTrue
    } else {
      query[KeychainSwiftConstants.returnData] =  kCFBooleanTrue
    }
    
    query = addAccessGroupWhenPresent(query)
    query = addSynchronizableIfRequired(query, addingItems: false)
    lastQueryParameters = query
    
    var result: AnyObject?
    
    lastResultCode = withUnsafeMutablePointer(to: &result) {
      SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
    }
    
    if lastResultCode == noErr {
      return result as? Data
    }
    
    return nil
  }
  
  public func secureGet(_ key: String, context: LAContext? = nil) -> String? {
    if let data = secureGetData(key, context: context) {
      
      if let currentString = String(data: data, encoding: .utf8) {
        return currentString
      }
      
      lastResultCode = -67853 // errSecInvalidEncoding
    }

    return nil
  }
  
  public func secureGetBool(_ key: String, context: LAContext? = nil) -> Bool? {
    guard let data = secureGetData(key, context: context) else { return nil }
    guard let firstBit = data.first else { return nil }
    return firstBit == 1
  }
}
