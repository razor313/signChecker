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
        return button
    }()
    
    lazy var verifyButton: UIButton = {
        let button = UIButton()
        button.translatesAutoresizingMaskIntoConstraints = false
        button.setTitle("Verify", for: .normal)
        button.setTitleColor(.systemBlue, for: .normal)
        button.layer.cornerRadius = 0.5
        return button
    }()
    
    lazy var signatureLabel: UILabel = {
        let label = UILabel()
        label.translatesAutoresizingMaskIntoConstraints = false
        label.text = "signature"
        label.textAlignment = .center
        return label
    }()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        self.view.backgroundColor = .white
        setupViews()
        // Do any additional setup after loading the view.
    }
    
    
}

extension ViewController {
    
    var MARGIN: Int {
        get { return 44 }
    }
    
    func setupViews() {
        setupScrollView()
        setupContainerView()
        setupTextField()
        setupSignButton()
        setupVerifyButton()
        setupSignatureLabel()
    }
    
    fileprivate func setupScrollView() {
        self.view.addSubview(scrollView)
        scrollView.snp.makeConstraints { make in
            make.edges.equalToSuperview()
        }
    }
    
    fileprivate func setupContainerView() {
        scrollView.addSubview(containerView)
        containerView.snp.makeConstraints { make in
            make.edges.equalToSuperview()
        }
    }
    
    fileprivate func setupTextField() {
        containerView.addSubview(textField)
        textField.snp.makeConstraints { make in
            make.top.equalToSuperview().offset(MARGIN)
            make.height.equalTo(MARGIN)
            make.centerX.equalToSuperview()
            make.width.equalToSuperview().multipliedBy(0.5)
        }
    }
    
    fileprivate func setupSignButton() {
        containerView.addSubview(signButton)
        signButton.snp.makeConstraints { make in
            make.height.equalTo(MARGIN)
            make.width.equalToSuperview().multipliedBy(0.33)
            make.centerX.equalToSuperview()
            make.top.equalTo(textField.snp.bottom).offset(MARGIN)
        }
    }
    
    fileprivate func setupVerifyButton() {
        containerView.addSubview(verifyButton)
        verifyButton.snp.makeConstraints { make in
            make.width.height.equalTo(signButton)
            make.top.equalTo(signButton.snp.bottom).offset(MARGIN)
            make.centerX.equalToSuperview()
        }
    }
    
    fileprivate func setupSignatureLabel() {
        containerView.addSubview(signatureLabel)
        signatureLabel.snp.makeConstraints { make in
            make.trailing.leading.equalToSuperview()
            make.top.equalTo(verifyButton.snp.bottom).offset(MARGIN)
        }
    }
}
