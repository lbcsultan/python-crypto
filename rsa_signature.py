import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QRadioButton, QButtonGroup
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import binascii

class RSASignatureApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.keyPair = None

    def initUI(self):
        layout = QVBoxLayout()

        # RSA 전자서명 소개
        intro_text = """
RSA 전자서명:
- RSA 알고리즘을 이용한 디지털 서명 방식입니다.
- 메시지의 무결성과 발신자의 인증을 제공합니다.
- 주요 특징:
  1. 개인키로 서명을 생성하고 공개키로 서명을 검증합니다.
  2. 메시지의 해시값에 대해 서명을 생성합니다.
  3. 부인 방지(Non-repudiation)를 제공합니다.
"""
        intro_label = QLabel(intro_text)
        intro_label.setWordWrap(True)
        layout.addWidget(intro_label)

        # 키 길이 선택
        key_length_group = QButtonGroup(self)
        key_length_layout = QHBoxLayout()
        key_length_layout.addWidget(QLabel("키 길이 선택:"))
        for length in [1024, 2048, 4096]:
            radio = QRadioButton(str(length))
            key_length_layout.addWidget(radio)
            key_length_group.addButton(radio)
        key_length_group.buttons()[1].setChecked(True)  # 2048 기본 선택
        layout.addLayout(key_length_layout)

        # 키 생성 버튼
        self.generateKeyButton = QPushButton('Generate RSA Keys')
        self.generateKeyButton.clicked.connect(lambda: self.generateKeys(key_length_group.checkedButton().text()))
        layout.addWidget(self.generateKeyButton)

        # 공개키 표시
        self.publicKeyDisplay = QTextEdit()
        self.publicKeyDisplay.setReadOnly(True)
        layout.addWidget(QLabel('Public Key:'))
        layout.addWidget(self.publicKeyDisplay)

        # 개인키 표시
        self.privateKeyDisplay = QTextEdit()
        self.privateKeyDisplay.setReadOnly(True)
        layout.addWidget(QLabel('Private Key:'))
        layout.addWidget(self.privateKeyDisplay)

        # 메시지 입력
        self.messageInput = QLineEdit()
        layout.addWidget(QLabel('Message:'))
        layout.addWidget(self.messageInput)

        # 서명 생성 버튼
        self.signButton = QPushButton('Sign Message')
        self.signButton.clicked.connect(self.sign_message)
        layout.addWidget(self.signButton)

        # 서명 표시
        self.signatureDisplay = QTextEdit()
        self.signatureDisplay.setReadOnly(True)
        layout.addWidget(QLabel('Signature:'))
        layout.addWidget(self.signatureDisplay)

        # 서명 검증 버튼
        self.verifyButton = QPushButton('Verify Signature')
        self.verifyButton.clicked.connect(self.verify_signature)
        layout.addWidget(self.verifyButton)

        # 검증 결과 표시
        self.verificationResult = QLineEdit()
        self.verificationResult.setReadOnly(True)
        layout.addWidget(QLabel('Verification Result:'))
        layout.addWidget(self.verificationResult)

        self.setLayout(layout)
        self.setWindowTitle('RSA Digital Signature Simulator')
        self.setGeometry(300, 300, 600, 800)

    def generateKeys(self, key_size):
        self.keyPair = RSA.generate(int(key_size))
        pubKey = self.keyPair.publickey()
        pubKeyPEM = pubKey.exportKey()
        self.publicKeyDisplay.setPlainText(pubKeyPEM.decode('ascii'))
        privKeyPEM = self.keyPair.exportKey()
        self.privateKeyDisplay.setPlainText(privKeyPEM.decode('ascii'))

    def sign_message(self):
        if not self.keyPair:
            self.signatureDisplay.setPlainText("Please generate keys first.")
            return
        message = self.messageInput.text().encode('utf-8')
        hash = SHA256.new(message)
        signer = pkcs1_15.new(self.keyPair)
        signature = signer.sign(hash)
        self.signatureDisplay.setPlainText(binascii.hexlify(signature).decode('ascii'))

    def verify_signature(self):
        if not self.keyPair:
            self.verificationResult.setText("Please generate keys first.")
            return
        message = self.messageInput.text().encode('utf-8')
        signature = binascii.unhexlify(self.signatureDisplay.toPlainText())
        hash = SHA256.new(message)
        verifier = pkcs1_15.new(self.keyPair.publickey())
        try:
            verifier.verify(hash, signature)
            self.verificationResult.setText("Signature is valid.")
        except (ValueError, TypeError):
            self.verificationResult.setText("Signature is invalid.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = RSASignatureApp()
    ex.show()
    sys.exit(app.exec_())
