//
//  ViewController.swift
//  signChecker
//
//  Created by Reza Dehnavi on 10/31/20.
//  Copyright © 2020 Reza Dehnavi. All rights reserved.
//

import UIKit
import SnapKit

class ViewController: UIViewController {
    
    lazy var textField: UITextField = {
        let textField = UITextField()
        textField.translatesAutoresizingMaskIntoConstraints = false
        textField.placeholder = "Enter text in order to sign"
        textField.borderStyle = .line
        textField.becomeFirstResponder()
        textField.tintColor = .systemBlue
        return textField
    }()
    
    lazy var scrollView: UIScrollView = {
        let scrollView = UIScrollView()
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        return scrollView
    }()
    
    lazy var containerView: UIView = {
        let view = UIView()
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()
    
    lazy var signButton: UIButton = {
        let button = UIButton()
        button.translatesAutoresizingMaskIntoConstraints = false
        button.setTitle("Sign", for: .normal)
        button.backgroundColor = .systemBlue
        button.addTarget(self, action: #selector(signData(_:)), for: .touchUpInside)
        return button
    }()
    
    lazy var verifyButton: UIButton = {
        let button = UIButton()
        button.translatesAutoresizingMaskIntoConstraints = false
        button.setTitle("Verify", for: .normal)
        button.setTitleColor(.systemBlue, for: .normal)
        button.layer.cornerRadius = 0.5
        button.addTarget(self, action: #selector(verifySign(_:)), for: .touchUpInside)
        return button
    }()
    
    lazy var signatureLabel: UILabel = {
        let label = UILabel()
        label.translatesAutoresizingMaskIntoConstraints = false
        label.text = "signature"
        label.textAlignment = .center
        label.numberOfLines = .zero
        label.lineBreakMode = .byWordWrapping
        return label
    }()
    
    var signatureData: Data?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        if #available(iOS 13.0, *) {
            self.view.backgroundColor = .systemBackground
        } else {
            self.view.backgroundColor = .white
        }
        setupViews()
        generateKeyPair()
        // Do any additional setup after loading the view.
    }
    
    fileprivate func generateKeyPair() {
        AsymmetricCryptoManager.sharedInstance.createSecureKeyPair { (flag, error) in
            flag ? print("The key pair was generated successfully!!!") : print("The key pair wasn't generated successfully!!!")
        }
    }
    
    @objc func verifySign(_ sender: UIButton) {
        self.view.endEditing(true)
        guard let publicKey = AsymmetricCryptoManager.sharedInstance.getSt() as Data? else { return }
        let exportImportManager = CryptoExportImportManager()
        if let key = exportImportManager.exportPublicKeyToPEM(publicKey as Data, keyType: kSecAttrKeyTypeEC as String, keySize: 256) {
            print(key)
        }
        let inputData = textField.text?.data(using: .utf8)
        AsymmetricCryptoManager.sharedInstance.verifySignaturePublicKey(inputData!, signatureData: signatureData!, completion: { (flag, error) in
            if flag {
                print("The sign is correct!!!")
            } else {
                print("The sign isn't correct!!!")
            }
        })
    }
    
    
    
    @objc func signData(_ sender: UIButton) {
        self.view.endEditing(true)
        guard let plainMessage = textField.text else { return }
        AsymmetricCryptoManager.sharedInstance.signMessageWithPrivateKey(plainMessage) { [weak self] (flag, data, error) in
            guard let self = self else { return }
            if flag {
                if let base64 = data?.base64EncodedString() {
                    print("the base64 encoding is: \(base64)")
                    print("The base64 signature length is: \(base64.count)")
                    self.signatureLabel.text = base64
                }
                var bytes = [UInt8](repeating:0, count:data!.count)
                data!.copyBytes(to: &bytes, count: (data?.count)!)
                let hexString = NSMutableString()
                for byte in bytes {
                    hexString.appendFormat("%02x", UInt(byte))
                }
                self.signatureData = data
                let hexSt = hexString as String
                print("The signature length is: \(hexSt.count)")
                print("The signature: \(hexSt)")
            } else {
                self.signatureLabel.text = "Sign oprate doesn't work properly."
            }
        }
    }
    
}
