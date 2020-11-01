//
//  AsymmetricCryptoManager.swift
//  AsymmetricCrypto
//
//  Created by Ignacio Nieto Carvajal on 4/10/15.
//  Copyright © 2015 Ignacio Nieto Carvajal. All rights reserved.
//

// Singleton instance
import Foundation
import Security
import CommonCrypto
import KeychainSwift

private var _singletonInstance: AsymmetricCryptoManager! = AsymmetricCryptoManager()

// Constants
private let kAsymmetricCryptoManagerApplicationTag = "com.irazor.signChecker"
private let kAsymmetricCryptoManagerCypheredBufferSize = 1024
private let kAsymmetricCryptoManagerSecPadding: SecPadding = .PKCS1
private let keychain = KeychainSwift(keyPrefix: kAsymmetricCryptoManagerApplicationTag)

enum AsymmetricCryptoException: Error {
    case unknownError
    case duplicateFoundWhileTryingToCreateKey
    case keyNotFound
    case authFailed
    case unableToAddPublicKeyToKeyChain
    case wrongInputDataFormat
    case unableToEncrypt
    case unableToDecrypt
    case unableToSignDatasi
    case unableToVerifySignedData
    case unableToPerformHashOfData
    case unableToGenerateAccessControlWithGivenSecurity
    case outOfMemory
}

class AsymmetricCryptoManager: NSObject {
    
    /** Shared instance */
    class var sharedInstance: AsymmetricCryptoManager {
        return _singletonInstance == nil ? AsymmetricCryptoManager() : _singletonInstance
    }
    
    func destroy() {
        _singletonInstance = nil
    }
    
    // MARK: - Manage keys
    func createSecureKeyPair(_ completion: ((_ success: Bool, _ error: AsymmetricCryptoException?) -> Void)? = nil) {
        
        // global parameters for our key generation
        let parameters = getParameters()
        
        // asynchronously generate the key pair and call the completion block
        DispatchQueue.global(qos: DispatchQoS.QoSClass.default).async { () -> Void in
            var pubKey, privKey: SecKey?
            let status = SecKeyGeneratePair(parameters as CFDictionary, &pubKey, &privKey)
            
            if status == errSecSuccess {
                DispatchQueue.main.async(execute: { completion?(true, nil) })
            } else {
                var error = AsymmetricCryptoException.unknownError
                switch (status) {
                case errSecDuplicateItem: error = .duplicateFoundWhileTryingToCreateKey
                case errSecItemNotFound: error = .keyNotFound
                case errSecAuthFailed: error = .authFailed
                default: break
                }
                DispatchQueue.main.async(execute: { completion?(false, error) })
            }
        }
    }
    
    private func getParameters() -> [String : Any] {
        return [
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPublicKeyAttrs as String: getPublicParameter(),
            kSecPrivateKeyAttrs as String: getPrivateParameters()
        ]
    }
    
    // private key parameters
    private func getPrivateParameters() -> [String : Any] {
        return [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: kAsymmetricCryptoManagerApplicationTag
        ]
    }
    
    // public key parameters
    private func getPublicParameter() -> [String: Any] {
        return [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: kAsymmetricCryptoManagerApplicationTag
        ]
    }
    
    func getSt() -> NSData? {
        let parameters : [String : Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrApplicationTag as String: kAsymmetricCryptoManagerApplicationTag,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecReturnData as String: true
        ]
        var data: AnyObject?
        let status = SecItemCopyMatching(parameters as CFDictionary, &data)
        if status == errSecSuccess {
            return data as? NSData
        } else { return nil }
    }
    
    fileprivate func getPublicKeyData() -> Data? {
        let parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrApplicationTag as String: kAsymmetricCryptoManagerApplicationTag,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecReturnData as String: true
            ] as [String : Any]
        var data: AnyObject?
        let status = SecItemCopyMatching(parameters as CFDictionary, &data)
        if status == errSecSuccess {
            return data as? Data
        } else { return nil }
    }
    
    fileprivate func getPublicKeyReference() -> SecKey? {
        let parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrApplicationTag as String: kAsymmetricCryptoManagerApplicationTag,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecReturnRef as String: true,
            ] as [String : Any]
        var ref: AnyObject?
        let status = SecItemCopyMatching(parameters as CFDictionary, &ref)
        if status == errSecSuccess { return ref as! SecKey? } else { return nil }
    }
    
    fileprivate func getPrivateECKeyReference() -> SecKey? {
        let parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: kAsymmetricCryptoManagerApplicationTag,
            kSecReturnRef as String: true,
            ] as [String : Any]
        var ref: AnyObject?
        let status = SecItemCopyMatching(parameters as CFDictionary, &ref)
        if status == errSecSuccess { return ref as! SecKey? } else { return nil }
    }
    
    fileprivate func getPrivateRSAKeyReference() -> SecKey? {
        let parameters = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: kAsymmetricCryptoManagerApplicationTag,
            kSecReturnRef as String: true,
            ] as [String : Any]
        var ref: AnyObject?
        let status = SecItemCopyMatching(parameters as CFDictionary, &ref)
        if status == errSecSuccess { return ref as! SecKey? } else { return nil }
    }
    
    func keyPairExists() -> Bool {
        return self.getPublicKeyData() != nil
    }
    
    func deleteSecureKeyPair(_ completion: ((_ success: Bool) -> Void)?) {
        // private query dictionary
        let deleteQuery = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: kAsymmetricCryptoManagerApplicationTag,
            ] as [String : Any]
        
        DispatchQueue.global(qos: DispatchQoS.QoSClass.default).async { () -> Void in
            let status = SecItemDelete(deleteQuery as CFDictionary) // delete private key
            DispatchQueue.main.async(execute: { completion?(status == errSecSuccess) })        }
    }
    // MARK: - Cypher and decypher methods
    
    func encryptMessageWithPublicKey(_ message: String, completion: @escaping (_ success: Bool, _ data: Data?, _ error: AsymmetricCryptoException?) -> Void) {
        DispatchQueue.global(qos: DispatchQoS.QoSClass.default).async { () -> Void in
            
            if let publicKeyRef = self.getPublicKeyReference() {
                // prepare input input plain text
                guard let messageData = message.data(using: String.Encoding.utf8) else {
                    completion(false, nil, .wrongInputDataFormat)
                    return
                }
                let plainText = (messageData as NSData).bytes.bindMemory(to: UInt8.self, capacity: messageData.count)
                let plainTextLen = messageData.count
                
                // prepare output data buffer
                var cipherData = Data(count: SecKeyGetBlockSize(publicKeyRef))
                let cipherText = cipherData.withUnsafeMutableBytes({ (bytes: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
                    return bytes
                })
                var cipherTextLen = cipherData.count
                
                let status = SecKeyEncrypt(publicKeyRef, .PKCS1, plainText, plainTextLen, cipherText, &cipherTextLen)
                
                // analyze results and call the completion in main thread
                DispatchQueue.main.async(execute: { () -> Void in
                    completion(status == errSecSuccess, cipherData, status == errSecSuccess ? nil : .unableToEncrypt)
                    cipherText.deinitialize(count: cipherData.count)
                })
                return
            } else { DispatchQueue.main.async(execute: { completion(false, nil, .keyNotFound) }) }
        }
    }
    
    func decryptMessageWithPrivateKey(_ encryptedData: Data, completion: @escaping (_ success: Bool, _ result: String?, _ error: AsymmetricCryptoException?) -> Void) {
        decryptMessageWithECPrivateKey(encryptedData, completion: completion)
    }
    
    func decryptMessageWithECPrivateKey(_ encryptedData: Data, completion: @escaping (_ success: Bool, _ result: String?, _ error: AsymmetricCryptoException?) -> Void) {
        DispatchQueue.global(qos: DispatchQoS.QoSClass.default).async { () -> Void in
            
            if let privateKeyRef = self.getPrivateECKeyReference() {
                // prepare input input plain text
                let encryptedText = (encryptedData as NSData).bytes.bindMemory(to: UInt8.self, capacity: encryptedData.count)
                let encryptedTextLen = encryptedData.count
                
                // prepare output data buffer
                var plainData = Data(count: kAsymmetricCryptoManagerCypheredBufferSize)
                let plainText = plainData.withUnsafeMutableBytes({ (bytes: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
                    return bytes
                })
                var plainTextLen = plainData.count
                
                let status = SecKeyDecrypt(privateKeyRef, .PKCS1, encryptedText, encryptedTextLen, plainText, &plainTextLen)
                
                // analyze results and call the completion in main thread
                DispatchQueue.main.async(execute: { () -> Void in
                    if status == errSecSuccess {
                        // adjust NSData length
                        plainData.count = plainTextLen
                        // Generate and return result string
                        if let string = NSString(data: plainData as Data, encoding: String.Encoding.utf8.rawValue) as String? {
                            completion(true, string, nil)
                        } else {
                            completion(false, nil, .unableToDecrypt) }
                    } else {
                        print("******", status)
                        completion(false, nil, .unableToDecrypt) }
                    plainText.deinitialize(count: plainTextLen)
                })
                return
            } else { DispatchQueue.main.async(execute: { completion(false, nil, .keyNotFound) }) }
        }
    }
    
    func decryptMessageWithRSAPrivateKey(_ encryptedData: Data, completion: @escaping (_ success: Bool, _ result: String?, _ error: AsymmetricCryptoException?) -> Void) {
        DispatchQueue.global(qos: DispatchQoS.QoSClass.default).async { () -> Void in
            
            if let privateKeyRef = self.getPrivateRSAKeyReference() {
                // prepare input input plain text
                let encryptedText = (encryptedData as NSData).bytes.bindMemory(to: UInt8.self, capacity: encryptedData.count)
                let encryptedTextLen = encryptedData.count
                
                // prepare output data buffer
                var plainData = Data(count: kAsymmetricCryptoManagerCypheredBufferSize)
                let plainText = plainData.withUnsafeMutableBytes({ (bytes: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
                    return bytes
                })
                var plainTextLen = plainData.count
                
                let status = SecKeyDecrypt(privateKeyRef, .PKCS1, encryptedText, encryptedTextLen, plainText, &plainTextLen)
                
                // analyze results and call the completion in main thread
                DispatchQueue.main.async(execute: { () -> Void in
                    if status == errSecSuccess {
                        // adjust NSData length
                        plainData.count = plainTextLen
                        // Generate and return result string
                        if let string = NSString(data: plainData as Data, encoding: String.Encoding.utf8.rawValue) as String? {
                            completion(true, string, nil)
                        } else {
                            completion(false, nil, .unableToDecrypt) }
                    } else {
                        print("******", status)
                        completion(false, nil, .unableToDecrypt) }
                    plainText.deinitialize(count: plainTextLen)
                })
                return
            } else { DispatchQueue.main.async(execute: { completion(false, nil, .keyNotFound) }) }
        }
    }
    
    // MARK: - Sign and verify signature.
    func signMessageWithPrivateKey(_ message: String, completion: @escaping (_ success: Bool, _ data: Data?, _ error: AsymmetricCryptoException?) -> Void) {
        signMessageWithPrivateKeyEC(message, completion: completion)
    }
    
    func signMessageWithPrivateKeyRSA(_ message: String, completion: @escaping (_ success: Bool, _ data: Data?, _ error: AsymmetricCryptoException?) -> Void) {
        DispatchQueue.global(qos: DispatchQoS.QoSClass.default).async { () -> Void in
            var error: AsymmetricCryptoException? = nil
            
            if let privateKeyRef = self.getPrivateRSAKeyReference() {
                // result data
                var resultData = Data(count: SecKeyGetBlockSize(privateKeyRef))
                let resultPointer = resultData.withUnsafeMutableBytes({ (bytes: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
                    return bytes
                })
                var resultLength = resultData.count
                
                if let plainData = message.data(using: String.Encoding.utf8) {
                    // generate hash of the plain data to sign
                    var hashData = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
                    let hash = hashData.withUnsafeMutableBytes({ (bytes: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
                        return bytes
                    })
                    CC_SHA256((plainData as NSData).bytes.bindMemory(to: Void.self, capacity: plainData.count), CC_LONG(plainData.count), hash)
                    
                    // sign the hash
                    let status = SecKeyRawSign(privateKeyRef, SecPadding.PKCS1SHA256, hash, hashData.count, resultPointer, &resultLength)
                    if status != errSecSuccess { error = .unableToEncrypt }
                    else { resultData.count = resultLength }
                    hash.deinitialize(count: resultLength)
                } else { error = .wrongInputDataFormat }
                
                // analyze results and call the completion in main thread
                DispatchQueue.main.async(execute: { () -> Void in
                    if error == nil {
                        // adjust NSData length and return result.
                        resultData.count = resultLength
                        completion(true, resultData as Data, nil)
                    } else { completion(false, nil, error) }
                    //resultPointer.destroy()
                })
            } else { DispatchQueue.main.async(execute: { completion(false, nil, .keyNotFound) }) }
        }
    }
    
    private func signMessageWithPrivateKeyEC(_ message: String, completion: @escaping (_ success: Bool, _ data: Data?, _ error: AsymmetricCryptoException?) -> Void) {
        DispatchQueue.global(qos: DispatchQoS.QoSClass.default).async { () -> Void in
            
            if let privateKeyRef = self.getPrivateECKeyReference() {
                let blockSize = 256
                var error: AsymmetricCryptoException? = nil
                var signatureBytes = [UInt8](repeating: 0, count: blockSize)
                var signatureLength = blockSize
                if let plainData = message.data(using: String.Encoding.utf8) {
                    
                    // generate hash of the plain data to sign
                    var hashData = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
                    let hash = hashData.withUnsafeMutableBytes({ (bytes: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
                        return bytes
                    })
                    CC_SHA256((plainData as NSData).bytes.bindMemory(to: Void.self, capacity: plainData.count), CC_LONG(plainData.count), hash)
                    
                    // sign the hash
                    let status = SecKeyRawSign(privateKeyRef, SecPadding.PKCS1SHA256, hash, hashData.count, &signatureBytes, &signatureLength)
                    if status != errSecSuccess {
                        error = .unableToEncrypt
                    } else {
                        
                    }
                } else {
                    error = .wrongInputDataFormat
                }
                
                // analyze results and call the completion in main thread
                DispatchQueue.main.async(execute: { () -> Void in
                    if error == nil {
                        // adjust NSData length and return result.
                        completion(true, Data(bytes: UnsafePointer<UInt8>(signatureBytes), count: signatureLength), nil)
                    } else { completion(false, nil, error) }
                    //resultPointer.destroy()
                })
            } else {
                DispatchQueue.main.async(execute: { completion(false, nil, .keyNotFound) })
            }
        }
    }
    
    func verifySignaturePublicKey(_ data: Data, signatureData: Data, completion: @escaping (_ success: Bool, _ error: AsymmetricCryptoException?) -> Void) {
        DispatchQueue.global(qos: DispatchQoS.QoSClass.default).async { () -> Void in
            var error: AsymmetricCryptoException? = nil
            
            if let publicKeyRef = self.getPublicKeyReference() {
                // hash data
                var hashData = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
                let hash = hashData.withUnsafeMutableBytes({ (bytes: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> in
                    return bytes
                })
                CC_SHA256((data as NSData).bytes.bindMemory(to: Void.self, capacity: data.count), CC_LONG(data.count), hash)
                // input and output data
                let signaturePointer = (signatureData as NSData).bytes.bindMemory(to: UInt8.self, capacity: signatureData.count)
                let signatureLength = signatureData.count
                
                let status = SecKeyRawVerify(publicKeyRef, SecPadding.PKCS1SHA256, hash, Int(CC_SHA256_DIGEST_LENGTH), signaturePointer, signatureLength)
                
                if status != errSecSuccess { error = .unableToDecrypt }
                
                // analyze results and call the completion in main thread
                hash.deinitialize(count: signatureLength)
                DispatchQueue.main.async(execute: { () -> Void in
                    completion(status == errSecSuccess, error)
                })
                return
            } else { DispatchQueue.main.async(execute: { completion(false, .keyNotFound) }) }
        }
    }
    
    
}




