import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QComboBox, QSpinBox, QGroupBox
from PyQt5.QtCore import Qt
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, SHA512
from Crypto.Random import get_random_bytes

class PBKDF2Tester(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # PBKDF2 소개
        intro_label = QLabel(
            "PBKDF2(Password-Based Key Derivation Function 2)는 패스워드를 기반으로 암호화 키를 생성하는 표준 함수입니다. "
            "이 함수는 다음과 같은 특징을 가집니다:\n"
            "1. 솔트(Salt) 사용: 무작위 값을 추가하여 동일한 패스워드로부터 다른 키를 생성합니다.\n"
            "2. 반복 횟수: 키 생성 과정을 여러 번 반복하여 무차별 대입 공격에 대한 저항성을 높입니다.\n"
            "3. 가변 길이 출력: 원하는 길이의 키를 생성할 수 있습니다.\n"
            "4. 다양한 해시 함수 지원: SHA-256, SHA-512 등 다양한 해시 함수를 사용할 수 있습니다.\n"
            "PBKDF2는 패스워드 저장, 키 생성 등 다양한 보안 애플리케이션에서 사용됩니다."
        )
        intro_label.setWordWrap(True)
        layout.addWidget(intro_label)

        # 공통 파라미터 그룹
        params_group = QGroupBox("공통 파라미터")
        params_layout = QVBoxLayout()

        # Salt 입력 및 생성
        salt_layout = QHBoxLayout()
        salt_label = QLabel('Salt:')
        salt_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        salt_label.setFixedWidth(80)
        salt_layout.addWidget(salt_label)
        self.salt_entry = QLineEdit()
        self.salt_entry.textChanged.connect(self.update_pbkdf2)
        salt_layout.addWidget(self.salt_entry)
        generate_salt_button = QPushButton('랜덤 생성')
        generate_salt_button.clicked.connect(self.generate_salt)
        salt_layout.addWidget(generate_salt_button)
        params_layout.addLayout(salt_layout)

        # 반복 횟수와 키 길이 입력
        params_input_layout = QHBoxLayout()
        params_input_layout.addWidget(QLabel('반복 횟수:'))
        self.iterations_spinbox = QSpinBox()
        self.iterations_spinbox.setRange(1, 1000000)
        self.iterations_spinbox.setValue(10000)
        self.iterations_spinbox.valueChanged.connect(self.update_pbkdf2)
        params_input_layout.addWidget(self.iterations_spinbox)
        params_input_layout.addWidget(QLabel('키 길이 (바이트):'))
        self.dklen_spinbox = QSpinBox()
        self.dklen_spinbox.setRange(1, 1024)
        self.dklen_spinbox.setValue(32)
        self.dklen_spinbox.valueChanged.connect(self.update_pbkdf2)
        params_input_layout.addWidget(self.dklen_spinbox)
        params_layout.addLayout(params_input_layout)

        # 해시 함수 선택
        hash_layout = QHBoxLayout()
        hash_layout.addWidget(QLabel('해시 함수:'))
        self.hash_combo = QComboBox()
        self.hash_combo.addItems(['SHA256', 'SHA512'])
        self.hash_combo.currentTextChanged.connect(self.update_pbkdf2)
        hash_layout.addWidget(self.hash_combo)
        params_layout.addLayout(hash_layout)

        params_group.setLayout(params_layout)
        layout.addWidget(params_group)

        # 송신자 그룹
        sender_group = QGroupBox("송신자")
        sender_layout = QVBoxLayout()

        sender_password_layout = QHBoxLayout()
        sender_password_label = QLabel('패스워드:')
        sender_password_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        sender_password_label.setFixedWidth(80)
        self.sender_password_entry = QLineEdit()
        self.sender_password_entry.textChanged.connect(self.update_pbkdf2)
        sender_password_layout.addWidget(sender_password_label)
        sender_password_layout.addWidget(self.sender_password_entry)
        sender_layout.addLayout(sender_password_layout)

        sender_key_layout = QHBoxLayout()
        sender_key_label = QLabel('PBKDF2 키:')
        sender_key_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        sender_key_label.setFixedWidth(80)
        self.sender_result_text = QLineEdit()
        self.sender_result_text.setReadOnly(True)
        sender_key_layout.addWidget(sender_key_label)
        sender_key_layout.addWidget(self.sender_result_text)
        sender_layout.addLayout(sender_key_layout)

        sender_group.setLayout(sender_layout)
        layout.addWidget(sender_group)

        # 수신자 그룹
        receiver_group = QGroupBox("수신자")
        receiver_layout = QVBoxLayout()

        receiver_password_layout = QHBoxLayout()
        receiver_password_label = QLabel('패스워드:')
        receiver_password_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        receiver_password_label.setFixedWidth(80)
        self.receiver_password_entry = QLineEdit()
        self.receiver_password_entry.textChanged.connect(self.update_pbkdf2)
        receiver_password_layout.addWidget(receiver_password_label)
        receiver_password_layout.addWidget(self.receiver_password_entry)
        receiver_layout.addLayout(receiver_password_layout)

        receiver_key_layout = QHBoxLayout()
        receiver_key_label = QLabel('PBKDF2 키:')
        receiver_key_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        receiver_key_label.setFixedWidth(80)
        self.receiver_result_text = QLineEdit()
        self.receiver_result_text.setReadOnly(True)
        receiver_key_layout.addWidget(receiver_key_label)
        receiver_key_layout.addWidget(self.receiver_result_text)
        receiver_layout.addLayout(receiver_key_layout)

        receiver_group.setLayout(receiver_layout)
        layout.addWidget(receiver_group)

        # 결과 비교
        self.comparison_result = QLabel()
        self.comparison_result.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.comparison_result)

        self.setLayout(layout)
        self.setWindowTitle('PBKDF2 테스터 (송신자-수신자)')
        self.setGeometry(300, 300, 800, 600)

    def generate_salt(self):
        salt = get_random_bytes(16)
        self.salt_entry.setText(salt.hex())

    def update_pbkdf2(self):
        sender_password = self.sender_password_entry.text().encode('utf-8')
        receiver_password = self.receiver_password_entry.text().encode('utf-8')
        salt = self.salt_entry.text()
        
        if salt:
            try:
                salt_bytes = bytes.fromhex(salt)
                iterations = self.iterations_spinbox.value()
                dklen = self.dklen_spinbox.value()
                hash_name = self.hash_combo.currentText()
                hash_module = SHA256 if hash_name == 'SHA256' else SHA512

                if sender_password:
                    sender_key = PBKDF2(sender_password, salt_bytes, dklen, count=iterations, hmac_hash_module=hash_module)
                    self.sender_result_text.setText(sender_key.hex())
                else:
                    self.sender_result_text.clear()

                if receiver_password:
                    receiver_key = PBKDF2(receiver_password, salt_bytes, dklen, count=iterations, hmac_hash_module=hash_module)
                    self.receiver_result_text.setText(receiver_key.hex())
                else:
                    self.receiver_result_text.clear()

                if sender_password and receiver_password:
                    if sender_key == receiver_key:
                        self.comparison_result.setText("결과 일치: 송신자와 수신자의 PBKDF2 결과가 같습니다.")
                        self.comparison_result.setStyleSheet("color: green;")
                    else:
                        self.comparison_result.setText("결과 불일치: 송신자와 수신자의 PBKDF2 결과가 다릅니다.")
                        self.comparison_result.setStyleSheet("color: red;")
                else:
                    self.comparison_result.setText("")
            except Exception as e:
                self.sender_result_text.setText(f"Error: {str(e)}")
                self.receiver_result_text.setText(f"Error: {str(e)}")
                self.comparison_result.setText("")
        else:
            self.sender_result_text.clear()
            self.receiver_result_text.clear()
            self.comparison_result.setText("")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PBKDF2Tester()
    ex.show()
    sys.exit(app.exec_())
