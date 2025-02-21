import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QRadioButton, QButtonGroup
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

class RSAEncryptionApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.keyPair = None

    def initUI(self):
        layout = QVBoxLayout()

        # RSA 소개
        intro_text = """
RSA (Rivest-Shamir-Adleman) 암호화 알고리즘:
- 1977년 MIT에서 개발된 공개키 암호 시스템입니다.
- 큰 정수의 소인수 분해의 어려움을 이용한 암호화 방식입니다.
- 공개키와 개인키 쌍을 사용하는 비대칭 암호화 방식입니다.
- 주요 특징:
  1. 데이터 암호화 및 전자서명에 사용 가능
  2. 전자상거래에서 널리 사용되는 알고리즘
  3. 키 교환이나 적은 양의 데이터 암호화에 주로 사용
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

        # 평문 입력
        self.plaintextInput = QLineEdit()
        layout.addWidget(QLabel('Plaintext:'))
        layout.addWidget(self.plaintextInput)

        # 암호화 버튼
        self.encryptButton = QPushButton('Encrypt')
        self.encryptButton.clicked.connect(self.encrypt)
        layout.addWidget(self.encryptButton)

        # 암호문 표시
        self.ciphertextDisplay = QTextEdit()
        self.ciphertextDisplay.setReadOnly(True)
        layout.addWidget(QLabel('Ciphertext:'))
        layout.addWidget(self.ciphertextDisplay)

        # 복호화 버튼
        self.decryptButton = QPushButton('Decrypt')
        self.decryptButton.clicked.connect(self.decrypt)
        layout.addWidget(self.decryptButton)

        # 복호화된 평문 표시
        self.decryptedDisplay = QLineEdit()
        self.decryptedDisplay.setReadOnly(True)
        layout.addWidget(QLabel('Decrypted Text:'))
        layout.addWidget(self.decryptedDisplay)

        self.setLayout(layout)
        self.setWindowTitle('RSA Encryption Simulator')
        self.setGeometry(300, 300, 600, 800)

    def generateKeys(self, key_size):
        self.keyPair = RSA.generate(int(key_size))
        pubKey = self.keyPair.publickey()
        pubKeyPEM = pubKey.exportKey()
        self.publicKeyDisplay.setPlainText(pubKeyPEM.decode('ascii'))
        privKeyPEM = self.keyPair.exportKey()
        self.privateKeyDisplay.setPlainText(privKeyPEM.decode('ascii'))

    def encrypt(self):
        if not self.keyPair:
            self.ciphertextDisplay.setPlainText("Please generate keys first.")
            return
        plaintext = self.plaintextInput.text().encode('utf-8')
        pubKey = self.keyPair.publickey()
        encryptor = PKCS1_OAEP.new(pubKey)
        encrypted = encryptor.encrypt(plaintext)
        self.ciphertextDisplay.setPlainText(binascii.hexlify(encrypted).decode('ascii'))

    def decrypt(self):
        if not self.keyPair:
            self.decryptedDisplay.setText("Please generate keys first.")
            return
        ciphertext = binascii.unhexlify(self.ciphertextDisplay.toPlainText())
        decryptor = PKCS1_OAEP.new(self.keyPair)
        decrypted = decryptor.decrypt(ciphertext)
        self.decryptedDisplay.setText(decrypted.decode('utf-8'))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = RSAEncryptionApp()
    ex.show()
    sys.exit(app.exec_())
