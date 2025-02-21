import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QRadioButton, QButtonGroup, QGroupBox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

class EncryptionApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # AES 소개
        intro_text = """
AES(Advanced Encryption Standard)는 현대 암호화에서 널리 사용되는 대칭키 암호화 알고리즘입니다.
주요 특징:
- 128비트 블록 크기 사용
- 128, 192, 256비트 키 길이 지원
- 대칭형, 블록 암호화, 양방향 암호화 방식
- 빠른 연산 속도 제공

운영 모드:
- ECB: 단순하지만 보안성 낮음
- CBC: IV 사용으로 보안성 향상
- CFB, OFB: 스트림 암호로 동작, 패딩 불필요
- CTR: 카운터 값 사용, 병렬 처리 가능
        """
        intro_label = QLabel(intro_text)
        intro_label.setWordWrap(True)
        layout.addWidget(intro_label)

        # 키 길이 선택 그룹
        key_length_group = QGroupBox("키 길이")
        key_length_layout = QHBoxLayout()
        self.key_length_group = QButtonGroup()
        for length in ['128', '192', '256']:
            radio = QRadioButton(length)
            key_length_layout.addWidget(radio)
            self.key_length_group.addButton(radio)
        self.key_length_group.buttons()[2].setChecked(True)  # 256비트 기본 선택
        key_length_group.setLayout(key_length_layout)
        layout.addWidget(key_length_group)

        # 운영 모드 선택 그룹
        mode_group = QGroupBox("운영 모드")
        mode_layout = QHBoxLayout()
        self.mode_group = QButtonGroup()
        for mode in ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']:
            radio = QRadioButton(mode)
            mode_layout.addWidget(radio)
            self.mode_group.addButton(radio)
        self.mode_group.buttons()[0].setChecked(True)  # ECB 기본 선택
        self.mode_group.buttonClicked.connect(self.update_params)
        mode_group.setLayout(mode_layout)
        layout.addWidget(mode_group)

        # 키 입력
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel('키:'))
        self.key_input = QLineEdit()
        self.key_input.setMinimumWidth(500)  # 키가 한 줄에 표시되도록 함
        key_layout.addWidget(self.key_input)
        self.generate_key_button = QPushButton('키 생성')
        self.generate_key_button.clicked.connect(self.generate_key)
        key_layout.addWidget(self.generate_key_button)
        layout.addLayout(key_layout)

        # 파라미터 표시
        self.params_label = QLabel('파라미터:')
        layout.addWidget(self.params_label)
        self.params_display = QLineEdit()
        self.params_display.setReadOnly(True)
        layout.addWidget(self.params_display)

        # 평문 입력
        layout.addWidget(QLabel('평문:'))
        self.plaintext_input = QTextEdit()
        self.plaintext_input.setPlainText("AES 암호화 테스트")
        layout.addWidget(self.plaintext_input)

        # 암호화 버튼
        self.encrypt_button = QPushButton('암호화')
        self.encrypt_button.clicked.connect(self.encrypt)
        layout.addWidget(self.encrypt_button)

        # 암호문 출력
        layout.addWidget(QLabel('암호문:'))
        self.ciphertext_output = QTextEdit()
        self.ciphertext_output.setReadOnly(True)
        layout.addWidget(self.ciphertext_output)

        # 복호화 버튼
        self.decrypt_button = QPushButton('복호화')
        self.decrypt_button.clicked.connect(self.decrypt)
        layout.addWidget(self.decrypt_button)

        # 복호화된 텍스트 출력
        layout.addWidget(QLabel('복호화된 텍스트:'))
        self.decrypted_output = QTextEdit()
        self.decrypted_output.setReadOnly(True)
        layout.addWidget(self.decrypted_output)

        self.setLayout(layout)
        self.setWindowTitle('AES 암호화/복호화')
        self.setGeometry(100, 100, 800, 700)  # 소개 텍스트를 위해 높이 증가
        self.generate_key()
        self.show()

    def generate_key(self):
        key_length = int(self.key_length_group.checkedButton().text())
        key = get_random_bytes(key_length // 8)
        self.key_input.setText(base64.b64encode(key).decode('utf-8'))
        self.update_params()

    def update_params(self):
        mode = self.mode_group.checkedButton().text()
        if mode == 'ECB':
            self.params_display.setText('추가 파라미터 없음')
        elif mode in ['CBC', 'CFB', 'OFB']:
            iv = get_random_bytes(16)
            self.params_display.setText(f'IV: {base64.b64encode(iv).decode("utf-8")}')
        elif mode == 'CTR':
            nonce = get_random_bytes(8)
            self.params_display.setText(f'Nonce: {base64.b64encode(nonce).decode("utf-8")}')

    def get_cipher(self, key, mode):
        if mode == 'ECB':
            return AES.new(key, AES.MODE_ECB), None
        elif mode in ['CBC', 'CFB', 'OFB']:
            iv = get_random_bytes(16)
            return AES.new(key, getattr(AES, f'MODE_{mode}'), iv), iv
        elif mode == 'CTR':
            nonce = get_random_bytes(8)
            return AES.new(key, AES.MODE_CTR, nonce=nonce), nonce

    def encrypt(self):
        key = base64.b64decode(self.key_input.text())
        plaintext = self.plaintext_input.toPlainText().encode('utf-8')
        mode = self.mode_group.checkedButton().text()

        cipher, param = self.get_cipher(key, mode)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        
        if param:
            encoded_data = base64.b64encode(param + ciphertext).decode('utf-8')
        else:
            encoded_data = base64.b64encode(ciphertext).decode('utf-8')
        self.ciphertext_output.setPlainText(encoded_data)

    def decrypt(self):
        try:
            key = base64.b64decode(self.key_input.text())
            encoded_data = self.ciphertext_output.toPlainText()
            mode = self.mode_group.checkedButton().text()
            
            encrypted_data = base64.b64decode(encoded_data)

            if mode != 'ECB':
                param = encrypted_data[:16 if mode != 'CTR' else 8]
                ciphertext = encrypted_data[16 if mode != 'CTR' else 8:]
                if mode == 'CTR':
                    cipher = AES.new(key, AES.MODE_CTR, nonce=param)
                else:
                    cipher = AES.new(key, getattr(AES, f'MODE_{mode}'), param)
            else:
                ciphertext = encrypted_data
                cipher = AES.new(key, AES.MODE_ECB)
            
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            self.decrypted_output.setPlainText(decrypted.decode('utf-8'))
        except ValueError as e:
            self.decrypted_output.setPlainText("복호화 실패: 잘못된 키 또는 손상된 데이터")
        except Exception as e:
            self.decrypted_output.setPlainText(f"복호화 오류: {str(e)}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = EncryptionApp()
    sys.exit(app.exec_())
