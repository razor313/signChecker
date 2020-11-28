//
//  Device.swift
//  signChecker
//
//  Created by Reza Dehnavi on 11/22/20.
//  Copyright © 2020 Reza Dehnavi. All rights reserved.
//

import LocalAuthentication

public enum Token {
    case secureEnclave
    case keychain
    
    public static var secureEnclaveIfAvailable: Token {
        return Device.hasSecureEnclave ? .secureEnclave : .keychain
    }
}

public enum Device {
    
    public static var hasTouchID: Bool {
        if #available(OSX 10.12.2, *) {
            return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        } else {
            return false
        }
    }
    
    public static var isSimulator: Bool {
        return TARGET_OS_SIMULATOR != 0
    }
    
    public static var hasSecureEnclave: Bool {
        return hasTouchID && !isSimulator
    }
    
}
