//
//  Config.swift
//  signChecker
//
//  Created by Reza Dehnavi on 11/22/20.
//  Copyright © 2020 Reza Dehnavi. All rights reserved.
//

import Foundation

public struct Config {
    
    // The label used to identify the public key in keychain
    public var publicLabel: String
    
    // The label used to identify the private key on the secure enclave
    public var privateLabel: String
    
    // The text presented to the user about why we need his/her fingerprint / device pin
    // If you are passing an LAContext to sign or decrypt this value will be rejected
    public var operationPrompt: String?
    
    // The access group e.g. "BBDV3R8HVV.no.agens.demo"
    // Useful for shared keychain items
    public var publicKeyAccessGroup: String?
    
    // The access group e.g. "BBDV3R8HVV.no.agens.demo"
    // Useful for shared keychain items
    public var privateKeyAccessGroup: String?
    
    
    // Should it be stored on .secureEnclave or in .keychain ?
    public var token: Token
    
    public init(publicLabel: String,
                privateLabel: String,
                operationPrompt: String?,
                publicKeyAccessGroup: String? = nil,
                privateKeyAccessGroup: String? = nil,
                token: Token) {
        self.publicLabel = publicLabel
        self.privateLabel = privateLabel
        self.operationPrompt = operationPrompt
        self.publicKeyAccessGroup = publicKeyAccessGroup
        self.privateKeyAccessGroup = privateKeyAccessGroup
        self.token = token
    }
}
