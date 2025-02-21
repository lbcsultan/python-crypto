import sys
import os
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QRadioButton, QButtonGroup, QFileDialog, QMessageBox
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime

class CertificateIssuanceApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.user_key = None
        self.ca_key = None
        self.ca_cert = None

    def initUI(self):
        layout = QVBoxLayout()

        intro_text = """
인증기관(CA)의 인증서 발급 시뮬레이션 프로그램:
1. CA 인증서를 생성합니다.
2. 사용자가 RSA 키 쌍을 생성합니다.
3. 사용자가 인증서 발급을 신청합니다.
4. 인증기관(CA)이 사용자의 공개키에 서명하여 인증서를 발급합니다.
5. 발급된 인증서는 사용자의 CN.crt 파일로, 개인키는 CN.key 파일로 저장됩니다.

주의: 이 프로그램은 교육 목적으로만 사용되어야 합니다.
"""
        intro_label = QLabel(intro_text)
        intro_label.setWordWrap(True)
        layout.addWidget(intro_label)

        # CA 인증서 생성 버튼
        self.generateCAButton = QPushButton('Generate CA Certificate')
        self.generateCAButton.clicked.connect(self.generate_ca_cert)
        layout.addWidget(self.generateCAButton)

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
        self.generateKeyButton = QPushButton('Generate User Key Pair')
        self.generateKeyButton.clicked.connect(lambda: self.generate_key_pair(int(key_length_group.checkedButton().text())))
        layout.addWidget(self.generateKeyButton)

        # 공개키 표시
        self.publicKeyDisplay = QTextEdit()
        self.publicKeyDisplay.setReadOnly(True)
        layout.addWidget(QLabel('User Public Key:'))
        layout.addWidget(self.publicKeyDisplay)

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
        self.issueCertButton = QPushButton('Issue Certificate')
        self.issueCertButton.clicked.connect(self.issue_cert)
        layout.addWidget(self.issueCertButton)

        # 인증서 표시
        self.certDisplay = QTextEdit()
        self.certDisplay.setReadOnly(True)
        layout.addWidget(QLabel('Issued Certificate:'))
        layout.addWidget(self.certDisplay)

        self.setLayout(layout)
        self.setWindowTitle('CA Certificate Issuance Simulator')
        self.setGeometry(300, 300, 600, 900)

    def generate_ca_cert(self):
        # CA 키 생성
        self.ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # CA 인증서 생성
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"KR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Seoul"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Seoul"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My CA Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"My CA"),
        ])
        self.ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(self.ca_key, hashes.SHA256())

        # CA 인증서 저장
        with open("cert.pem", "wb") as f:
            f.write(self.ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open("cert.crt", "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

        QMessageBox.information(self, "성공", "CA 인증서가 생성되었습니다.")

    def generate_key_pair(self, key_size):
        self.user_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        public_key = self.user_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        self.publicKeyDisplay.setPlainText(public_key)

    def issue_cert(self):
        if not self.user_key:
            QMessageBox.warning(self, "경고", "먼저 사용자 키 쌍을 생성해주세요.")
            return
        if not self.ca_key or not self.ca_cert:
            QMessageBox.warning(self, "경고", "먼저 CA 인증서를 생성해주세요.")
            return

        cn = self.subjectInfo['CN'].text()
        if not cn:
            QMessageBox.warning(self, "경고", "Common Name (CN)을 입력해주세요.")
            return

        # 인증서 생성
        subject = x509.Name([
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
            self.ca_cert.subject
        ).public_key(
            self.user_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]),
            critical=False,
        ).sign(self.ca_key, hashes.SHA256())

        # 인증서를 PEM 형식으로 변환
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        self.certDisplay.setPlainText(cert_pem)

        # 인증서 저장
        cert_filename = f"{cn}.crt"
        with open(cert_filename, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # 개인키 저장
        key_filename = f"{cn}.key"
        with open(key_filename, "wb") as f:
            f.write(self.user_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        QMessageBox.information(self, "성공", f"인증서가 {cert_filename}로, 개인키가 {key_filename}로 저장되었습니다.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = CertificateIssuanceApp()
    ex.show()
    sys.exit(app.exec_())
