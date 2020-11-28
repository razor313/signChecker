//
//  SignerHelper.swift
//  signChecker
//
//  Created by Reza Dehnavi on 11/22/20.
//  Copyright © 2020 Reza Dehnavi. All rights reserved.
//

import Security
import LocalAuthentication

class SignerHelper {
    
    let config: Config
    
    var cashedPublicKey: SecKey?
    var cashedPrivateKey: SecKey?
    
    public init(config: Config) {
        self.config = config
    }
    
    func getPrivateParameter() -> [String : Any]? {
        var error: Unmanaged<CFError>?
        let flags: SecAccessControlCreateFlags = [.privateKeyUsage, .touchIDAny]
        guard let aclObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, flags, &error) else {
            print("could not create ACL error")
            return nil
        }
        return [
            kSecAttrAccessControl as String: aclObject as AnyObject, //protect with touch id
            kSecAttrIsPermanent as String: true
        ]
    }
    
    func getKey(_ query: [String : AnyObject]) -> SecKey? {
        var raw: AnyObject?
        print("SecItemCopyMatching: \(query)")
        let status = SecItemCopyMatching(query as CFDictionary, &raw)
        guard status == errSecSuccess, let result = raw else {
            print("message: Could not get key for query: \(query), osStatus: \(status)")
            return nil
        }
        return (result as! SecKey)
    }
    
    
    
    func getPrivateKeyQuery(_ localReason: String? = nil) -> [String : Any] {
        let context = LAContext()
        context.localizedReason = localReason ?? config.operationPrompt ?? ""
        var params: [String:Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrLabel as String: config.privateLabel,
            kSecUseAuthenticationContext as String: context,
            kSecReturnRef as String: true
        ]
        if let accessGroup = config.privateKeyAccessGroup {
            params[kSecAttrAccessGroup as String] = accessGroup
        }
        return params
    }
    
    func getPublicKeyQuery() -> [String : Any] {
        var params: [String:Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrLabel as String: config.publicLabel,
            kSecReturnRef as String: true,
        ]
        if let accessGroup = config.publicKeyAccessGroup {
            params[kSecAttrAccessGroup as String] = accessGroup
        }
        return params
    }
    
    func getKeyPairQuery(context: LAContext? = nil) -> [String : Any] {
        /* ========= private ========= */
        var privateKeyParams: [String: Any] = [
            kSecAttrLabel as String: config.privateLabel,
            kSecAttrIsPermanent as String: true,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIAllow
        ]
        if let privateKeyAccessGroup = config.privateKeyAccessGroup {
            privateKeyParams[kSecAttrAccessGroup as String] = privateKeyAccessGroup
        }
        if let context = context {
            privateKeyParams[kSecUseAuthenticationContext as String] = context
        }
        
        // On iOS 11 and lower: access control with empty flags doesn't work
        if let aclObject = config.privateKeyAccessControl {
            privateKeyParams[kSecAttrAccessControl as String] = aclObject
        }
        /* ========= public ========= */
        var publicKeyParams: [String: Any] = [
            kSecAttrLabel as String: config.publicLabel,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        if let publicKeyAccessGroup = config.publicKeyAccessGroup {
            publicKeyParams[kSecAttrAccessGroup as String] = publicKeyAccessGroup
        }
        
        /* ========= combined ========= */
        var params: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecPrivateKeyAttrs as String: privateKeyParams,
            kSecPublicKeyAttrs as String: publicKeyParams,
            kSecAttrKeySizeInBits as String: 256
        ]
        if config.token == .secureEnclave {
            params[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }
        
        return params
    }
    
    private func generateKeyPair(context: LAContext? = nil) -> (`publicKey`: SecKey?, `privateKey`: SecKey?) {
        if config.privateLabel == config.publicLabel {
            print("message: Public key and private key can not have same label")
            return (publicKey: nil, privateKey: nil)
        }
        let context = context ?? LAContext()
        let query = getKeyPairQuery(context: context)
        var publicOptional, privateOptional: SecKey?
        let status = SecKeyGeneratePair(query as CFDictionary, &publicOptional, &privateOptional)
        guard status == errSecSuccess else { return (publicKey: publicOptional, privateKey: privateOptional) }
        forceSavePublicKey(publicOptional!)
        return (publicKey: publicOptional, privateKey: privateOptional)
    }
    
    public func sign(_ digest: Data, localReason: String? = nil) -> Data? {
        let privateKey = getPrivateKey(localReason: localReason)
        var error: Unmanaged<CFError>?
        let result = SecKeyCreateSignature(privateKey!, .ecdsaSignatureMessageX962SHA256, digest as CFData, &error)
        guard let signature = result else {
            print("message: Could not create signature.")
            return nil
        }
        return signature as Data
    }
    
    private func forceSavePublicKey(_ publicKey: SecKey) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrLabel as String: config.publicLabel,
            kSecValueRef as String: publicKey
        ]
        var raw: CFTypeRef?
        var status = SecItemAdd(query as CFDictionary, &raw)
        if status == errSecDuplicateItem {
            status = SecItemDelete(query as CFDictionary)
            status = SecItemAdd(query as CFDictionary, &raw)
        }
        if status == errSecInvalidRecord {
            print("message: Could not save public key. It is possible that the access control you have provided is not supported on this OS and/or hardware.")
        } else if status != errSecSuccess {
            print("message: Could not save public key")
        }
    }
    
    public func getPrivateKey(localReason: String? = nil) -> SecKey? {
        let query = getPrivateKeyQuery(localReason) as [String : AnyObject]
        guard let result = getKey(query) else { return nil }
        return result
    }
    
    public func getPublicKey() -> SecKey? {
        if let publicKey = cashedPublicKey {
            return publicKey
        }
        let query = getPublicKeyQuery() as [String : AnyObject]
        guard let result = getKey(query) else {
            let keys = generateKeyPair()
            cashedPrivateKey = keys.privateKey
            cashedPublicKey = keys.publicKey
            return keys.publicKey
        }
        cashedPublicKey = result
        return result
    }
    
    public func isKeyexist() -> Bool {
        guard let _ = getPublicKey() else { return false }
        return true
    }
    
    private func getKey(query: [String : Any]) -> SecKey? {
        var raw: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &raw)
        if let result = raw, status == errSecSuccess {
            return (result as! SecKey)
        }
        print("message: Could not get key for query: \(query)")
        return nil
    }
    
    public func deleteKeyPair() {
        clearCache()
        delete()
    }
    
    private func clearCache() {
        cashedPublicKey = nil
        cashedPrivateKey = nil
    }
    
    private func delete() {
        deletePublicKey()
        deletePrivateKey()
    }
    
    private func deletePublicKey() {
        let query = getPublicKeyQuery() as CFDictionary
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            print("[ERROR] message: Could not delete public key. \(query)")
            return
        }
        print("[INFO] message: Could delete public key. \(query)")
    }
    
    private func deletePrivateKey() {
        let query = getPrivateKeyQuery() as CFDictionary
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            print("[ERROR] message: Could not delete private key. \(query)")
            return
        }
        print("[INFO] message: Could delete private key. \(query)")
    }
    
    public func getPEM(_ publicKeyData: Data) -> String {
        var pem = String()
        pem.append("-----BEGIN PUBLIC KEY-----\n")
        pem.append(publicKeyData.base64EncodedString(options: [.lineLength64Characters, .endLineWithCarriageReturn]))
        pem.append("\n-----END PUBLIC KEY-----")
        return pem
    }
    
    public func verifyUsingSha256(signature: Data, digest: Data, publicKey: SecKey) -> Bool {
        let flag: Bool = false
        let sha = digest.sha256()
        var shaBytes = [UInt8](repeating: 0, count: sha.count)
        sha.copyBytes(to: &shaBytes, count: sha.count)
        
        var signatureBytes = [UInt8](repeating: 0, count: signature.count)
        signature.copyBytes(to: &signatureBytes, count: signature.count)
        
        let status = SecKeyRawVerify(publicKey, .PKCS1, &shaBytes, shaBytes.count, &signatureBytes, signatureBytes.count)
        guard status == errSecSuccess else {
            print("message: Could not verify signature.")
            return true
        }
        return flag
    }
}
