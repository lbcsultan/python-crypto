import sys
import os
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QRadioButton, QButtonGroup, QFileDialog, QMessageBox
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime

class CertificateGeneratorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.key = None

    def initUI(self):
        layout = QVBoxLayout()

        # 인증서 발급 소개
        intro_text = """
자체 서명 인증서 발급 프로그램:
- RSA 키 쌍을 생성합니다.
- X.509 형식의 자체 서명 인증서를 발급합니다.
- 인증서는 공개키 인증에 사용됩니다.
"""
        intro_label = QLabel(intro_text)
        intro_label.setWordWrap(True)
        layout.addWidget(intro_label)

        # 키 길이 선택
        key_length_group = QButtonGroup(self)
        key_length_layout = QHBoxLayout()
        key_length_layout.addWidget(QLabel("키 길이 선택:"))
        for length in [2048, 3072, 4096]:
            radio = QRadioButton(str(length))
            key_length_layout.addWidget(radio)
            key_length_group.addButton(radio)
        key_length_group.buttons()[0].setChecked(True)  # 2048 기본 선택
        layout.addLayout(key_length_layout)

        # 키 생성 버튼
        self.generateKeyButton = QPushButton('Generate Key Pair')
        self.generateKeyButton.clicked.connect(lambda: self.generate_key_pair(int(key_length_group.checkedButton().text())))
        layout.addWidget(self.generateKeyButton)

        # 공개키 표시
        self.publicKeyDisplay = QTextEdit()
        self.publicKeyDisplay.setReadOnly(True)
        layout.addWidget(QLabel('Public Key:'))
        layout.addWidget(self.publicKeyDisplay)

        # 개인키 표시
        self.privateKeyDisplay = QTextEdit()
        self.privateKeyDisplay.setReadOnly(True)
        layout.addWidget(QLabel('Private Key (주의: 실제 환경에서는 절대 표시하지 마세요):'))
        layout.addWidget(self.privateKeyDisplay)

        # 주체 정보 입력
        self.subjectInfo = {}
        default_values = {
            'CN': 'example.com',
            'O': 'Example Organization',
            'OU': 'IT Department',
            'L': 'Seoul',
            'ST': 'Seoul',
            'C': 'KR'
        }
        for field, default in default_values.items():
            field_layout = QHBoxLayout()
            field_layout.addWidget(QLabel(f"{field}:"))
            self.subjectInfo[field] = QLineEdit(default)
            field_layout.addWidget(self.subjectInfo[field])
            layout.addLayout(field_layout)

        # 인증서 발급 버튼
        self.generateCertButton = QPushButton('Generate Certificate')
        self.generateCertButton.clicked.connect(self.generate_cert)
        layout.addWidget(self.generateCertButton)

        # 인증서 표시
        self.certDisplay = QTextEdit()
        self.certDisplay.setReadOnly(True)
        layout.addWidget(QLabel('Certificate:'))
        layout.addWidget(self.certDisplay)

        self.setLayout(layout)
        self.setWindowTitle('Self-Signed Certificate Generator')
        self.setGeometry(300, 300, 600, 900)

    def generate_key_pair(self, key_size):
        self.key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        public_key = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        private_key = self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        self.publicKeyDisplay.setPlainText(public_key)
        self.privateKeyDisplay.setPlainText(private_key)

    def generate_cert(self):
        if not self.key:
            QMessageBox.warning(self, "경고", "먼저 키 쌍을 생성해주세요.")
            return

        cn = self.subjectInfo['CN'].text()
        if not cn:
            QMessageBox.warning(self, "경고", "Common Name (CN)을 입력해주세요.")
            return

        # 인증서 생성
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.subjectInfo['C'].text()),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.subjectInfo['ST'].text()),
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.subjectInfo['L'].text()),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.subjectInfo['O'].text()),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.subjectInfo['OU'].text()),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]),
            critical=False,
        ).sign(self.key, hashes.SHA256())

        # 인증서를 PEM 형식으로 변환
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        self.certDisplay.setPlainText(cert_pem)

        # 개인키 저장
        private_key_filename = f"{cn}.pem"
        with open(private_key_filename, 'wb') as f:
            f.write(self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # 인증서 저장
        cert_filename = f"{cn}.crt"
        with open(cert_filename, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        QMessageBox.information(self, "성공", f"개인키가 {private_key_filename}로, 인증서가 {cert_filename}로 저장되었습니다.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = CertificateGeneratorApp()
    ex.show()
    sys.exit(app.exec_())
