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
import CryptoKit

// Constants
private let kAsymmetricCryptoManagerApplicationTag = "com.irazor.signChecker"
private let kAsymmetricCryptoManagerCypheredBufferSize = 1024
private let kAsymmetricCryptoManagerSecPadding: SecPadding = .PKCS1

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

final class AsymmetricCryptoManager {
    
    /** Shared instance */
    static var sharedInstance: AsymmetricCryptoManager = AsymmetricCryptoManager()
    
    private init() {
        if let (tempECCSignPrivateKey, tempECCSignPublicKey) = getECCSignKeysRef() {
            eCCSignPrivateKey = tempECCSignPrivateKey
            eCCSignPublicKey = tempECCSignPublicKey
            eCCSignKeyExists = true
            print("The key pair is existed!!!")
            print("ECC keys", tempECCSignPublicKey, tempECCSignPrivateKey)
        }
    }
    
    let kSecMessECCKeyType = kSecAttrKeyTypeEC
    let kSecMessECCKeySize = 256
    let kSecMessECCSignLabel = "ECCLabelForSigning3"
    private let kSecMessECCApplicationTag = "com.secmessecc.key"
    private let kSecMessECCLabel = "notouch.secmessdecry.ecckey"
    var eCCKeyExists = false
    var eCCSignKeyExists = false
    var eCCSignPrivateKey, eCCSignPublicKey: SecKey?
    
    // MARK: - Manage keys
    func createSecureKeyPair(_ completion: ((_ success: Bool, _ error: AsymmetricCryptoException?) -> Void)? = nil) {
        
        print("generate a key pair")
        if eCCSignKeyExists {
            completion?(true, nil)
            return
        }
        
        // global parameters for our key generation
        let parameters = getParameters()
        
        // asynchronously generate the key pair and call the completion block
        DispatchQueue.global(qos: DispatchQoS.QoSClass.default).async { () -> Void in
            guard let eCCPrivKey = SecKeyCreateRandomKey(parameters as CFDictionary, nil) else {
                print("ECC KeyGen Error!")
                DispatchQueue.main.async(execute: { completion?(false, AsymmetricCryptoException.unableToGenerateAccessControlWithGivenSecurity) })
                return
            }
            guard let eCCPubKey = SecKeyCopyPublicKey(eCCPrivKey) else {
                DispatchQueue.main.async(execute: { completion?(false, AsymmetricCryptoException.unableToGenerateAccessControlWithGivenSecurity) })
                return
            }
            print("ECC keys", eCCPubKey, eCCPrivKey)
            
            self.eCCSignPublicKey = eCCPubKey
            self.eCCSignPrivateKey = eCCPrivKey
            self.eCCKeyExists = true
            //serialize b64 to share public key
            let externalKey = SecKeyCopyExternalRepresentation(eCCPubKey, nil)
            if let externalKeyData = externalKey as Data? {
                let externalKeyB64String = externalKeyData.base64EncodedString(options: [])
                print("ECC external key b64", externalKeyB64String)
                DispatchQueue.main.async(execute: { completion?(true, nil) })
            }
        }
    }
    
    func signECCPrivKey(message: String) -> String {
        print("signing with private key")
        guard let messageData = message.data(using: String.Encoding.utf8) else {
            print("bad message to sign")
            return ""
        }
        //finger print proteted SHA256 X 96
        guard let signData = SecKeyCreateSignature(eCCSignPrivateKey!, SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256, messageData as CFData, nil) else {
            print("priv ECC error signing")
            return ""
        }
        
        //convert signed to base64 string
        let signedData = signData as Data
        let signedString = signedData.base64EncodedString(options: [])
        print("priv signed string", signedString)
        return signedString
    }
    
    private func getParameters() -> [String : Any] {
        return [
             kSecAttrTokenID as String:          kSecAttrTokenIDSecureEnclave,
             kSecAttrKeyType as String:          kSecMessECCKeyType,
             kSecAttrKeySizeInBits as String:    kSecMessECCKeySize as AnyObject,
             kSecAttrLabel as String:            kSecMessECCSignLabel as AnyObject,
             kSecPrivateKeyAttrs as String:      getPrivateParameters() as AnyObject
         ]
    }
    
    // private key parameters
    private func getPrivateParameters() -> [String : Any] {
        guard
        let aclObject = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .touchIDAny],
            nil
            ) else {
            print("could not create ACL error")
            return [:]
        }
        return [
            kSecAttrAccessControl as String: aclObject as AnyObject, //protect with touch id
            kSecAttrIsPermanent as String: true
        ]
    }
    
    private func getECCPrivateKeyRef() -> SecKey? {
            let parameters: [String: AnyObject] = [
                kSecClass as String:                kSecClassKey,
                kSecAttrKeyType as String:          kSecMessECCKeyType,
                kSecAttrKeySizeInBits as String:    kSecMessECCKeySize as AnyObject,
                kSecAttrLabel as String:            kSecMessECCLabel as AnyObject,
                kSecReturnRef as String:            true as AnyObject,
                kSecUseOperationPrompt as String:   "Authenticate to access keys" as AnyObject
            ]
            var eCCPrivKey: AnyObject?
            let status = SecItemCopyMatching(parameters as CFDictionary, &eCCPrivKey)
            if status != noErr {
                print("ECC Priv KeyGet Error!", status)
                return nil
            }
            print("found ECC priv key in keychain", eCCPrivKey as! SecKey)
            return (eCCPrivKey as! SecKey)
    }
    
    private func getECCSignKeysRef() -> (SecKey, SecKey)? {
        guard let eCCPrivKey = getECCSignPrivateKeyRef() else {
            print("ECC Pub Priv KeyGet Error")
            return nil
        }
        guard let eCCPubKey = SecKeyCopyPublicKey(eCCPrivKey) else {
            print("ECC Pub KeyGet Error")
            return nil
        }
        print("found ECC pub key in keychain", eCCPubKey, eCCPrivKey)
        return (eCCPrivKey, eCCPubKey)
    }
    
    private func getECCSignPrivateKeyRef() -> SecKey? {
        let parameters: [String: AnyObject] = [
            kSecClass as String:                kSecClassKey,
            kSecAttrKeyType as String:          kSecMessECCKeyType,
            kSecAttrKeySizeInBits as String:    kSecMessECCKeySize as AnyObject,
            kSecAttrLabel as String:            kSecMessECCSignLabel as AnyObject,
            kSecReturnRef as String:            true as AnyObject,
            kSecUseOperationPrompt as String:   "Authenticate to access keys" as AnyObject
        ]
        var eCCPrivKey: AnyObject?
        let status = SecItemCopyMatching(parameters as CFDictionary, &eCCPrivKey)
        if status != noErr {
            print("ECC Priv KeyGet Error!", status)
            return nil
        }
        print("found ECC priv key in keychain", eCCPrivKey as! SecKey)
        return (eCCPrivKey as! SecKey)
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
            kSecAttrLabel as String: kSecMessECCSignLabel as AnyObject,
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
            
            if let privateKeyRef = self.getECCSignPrivateKeyRef() {
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
//                    let status = SecKeyRawSign(privateKeyRef, SecPadding.PKCS1SHA256, hash, hashData.count, &signatureBytes, &signatureLength)
                    let status = SecKeyCreateSignature(privateKeyRef, .ecdsaSignatureMessageX962SHA256, plainData as CFData, nil)
                    if status == nil {
                        error = .unableToEncrypt
                    } else {
                        DispatchQueue.main.async(execute: { () -> Void in
                            completion(true, status! as Data, nil)
                        })
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
    
    /*
    func getPrivateParameterForECCKey() -> [String : AnyObject]? {
        guard
        let aclObject = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .touchIDAny],
            nil
            ) else {
            print("could not create ACL error")
            return nil
        }
                
        // private key parameters
        let privateKeyParams: [String: AnyObject] = [
            kSecAttrAccessControl as String:    aclObject as AnyObject, //protect with touch id
            kSecAttrIsPermanent as String:      true as AnyObject,
        ]
        return privateKeyParams
    }
    
    func getGlobalParameterForECCKey() -> [String : AnyObject]? {
        guard let privateKeyParams = getPrivateParameterForECCKey() else { return nil }
        let parameters: [String: AnyObject] = [
            kSecAttrTokenID as String:          kSecAttrTokenIDSecureEnclave,
            kSecAttrKeyType as String:          kSecMessECCKeyType,
            kSecAttrKeySizeInBits as String:    kSecMessECCKeySize as AnyObject,
            kSecAttrLabel as String:            kSecMessECCSignLabel as AnyObject,
            kSecPrivateKeyAttrs as String:      privateKeyParams as AnyObject
        ]
        return parameters
    }
    
    func createECCKeyPair() -> (SecKey?, SecKey?) {
        guard let parameters = getGlobalParameterForECCKey() else { return (nil, nil) }
        guard
        let eCCPrivKey = SecKeyCreateRandomKey(parameters as CFDictionary, nil) else {
            print("ECC KeyGen Error!")
            return (nil, nil)
        }

        guard
        let eCCPubKey = SecKeyCopyPublicKey(eCCPrivKey) else {
            print("ECC Pub KeyGen Error")
            return (nil, nil)
        }
        return (publicKey: eCCPubKey, privateKey: eCCPrivKey)
    }
    
    func signWithECCKeyMessage(_ message: String) {
        let (_, privateKey) = createECCKeyPair()
        guard let messageData = message.data(using: String.Encoding.utf8) else {
            print("bad message to sign")
            return
        }
        guard
        let signData = SecKeyCreateSignature(
                       privateKey!,
                       SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256,
                       messageData as CFData, nil) else {
            print("priv ECC error signing")
            return
        }
        let signedData = signData as Data
        let signature = signedData.base64EncodedString()
        print("priv signed string", signature)
    }
 */
}




