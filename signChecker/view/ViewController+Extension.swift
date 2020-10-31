//
//  ViewController+Extension.swift
//  signChecker
//
//  Created by Reza Dehnavi on 10/31/20.
//  Copyright © 2020 Reza Dehnavi. All rights reserved.
//

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
