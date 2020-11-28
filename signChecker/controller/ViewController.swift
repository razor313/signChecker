//
//  ViewController.swift
//  signChecker
//
//  Created by Reza Dehnavi on 10/31/20.
//  Copyright © 2020 Reza Dehnavi. All rights reserved.
//

import UIKit
import SnapKit
import LocalAuthentication

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
    
    let context = LAContext()
    
    struct Helper {
        static let signer: SignerHelper = {
            return SignerHelper(config: Config(publicLabel: "ir.publicLabel1", privateLabel: "ir.privateLabel1", operationPrompt: "The biometric need authenticate", publicKeyAccessGroup: nil, privateKeyAccessGroup: nil, token: .secureEnclaveIfAvailable))
        }()
    }
    
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
        guard let publicKey = Helper.signer.getPublicKey() else { return }
        guard let publicKeyString = getData(publicKey: publicKey)?.base64EncodedString(options: []) else { return }
        print(publicKeyString)
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
        guard let plainMessage = textField.text, let messageData = plainMessage.data(using: .utf8) else { return }
        let signatureData = Helper.signer.sign(messageData, localReason: "need for sign")
        signatureLabel.text = signatureData?.base64EncodedString(options: [])
    }
    
    private func getData(publicKey: SecKey) -> Data? {
        var error : Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            print("message: Can't to tried reading public key bytes.")
            return nil
        }
        return raw as Data
    }
    
}
