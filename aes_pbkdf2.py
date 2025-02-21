import sys
import json
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QRadioButton, QButtonGroup, QGroupBox, QSplitter
from PyQt5.QtGui import QFont
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

class EncryptionApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        main_layout = QHBoxLayout()
        
        # 좌측 설명 부분
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        
        explanation_text = """
        <h2>AES (Advanced Encryption Standard) 암호화 알고리즘</h2>
        <p>AES는 대칭키 암호화 알고리즘으로, 128비트 블록 크기를 사용합니다.</p>
        <p>키 길이: 128, 192, 256 비트를 지원합니다.</p>
        <h3>운영 모드:</h3>
        <ul>
        <li>ECB (Electronic Codebook): 가장 단순하지만 보안성이 낮습니다.</li>
        <li>CBC (Cipher Block Chaining): IV를 사용하여 보안성을 높입니다.</li>
        <li>CFB (Cipher Feedback): 스트림 암호처럼 동작합니다.</li>
        <li>OFB (Output Feedback): CFB와 유사하지만 다음 블록 암호화에 사용하는 데이터가 다릅니다.</li>
        <li>CTR (Counter): 카운터 값을 사용하여 병렬 처리가 가능합니다.</li>
        </ul>
        <h3>PBKDF2 (Password-Based Key Derivation Function 2):</h3>
        <p>패스워드로부터 안전한 암호화 키를 생성하는 함수입니다.</p>
        <h3>인코딩 방식:</h3>
        <p>Base64: 바이너리 데이터를 ASCII 문자열로 변환하는 인코딩 방식입니다.</p>
        <p>JSON: 구조화된 데이터를 표현하는 텍스트 기반의 데이터 교환 형식입니다.</p>
        """
        
        explanation_label = QLabel(explanation_text)
        explanation_label.setWordWrap(True)
        left_layout.addWidget(explanation_label)
        
        left_widget.setLayout(left_layout)
        
        # 우측 시뮬레이션 부분
        right_widget = QWidget()
        right_layout = QVBoxLayout()

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
        right_layout.addWidget(key_length_group)

        # 운영 모드 선택 그룹
        mode_group = QGroupBox("운영 모드")
        mode_layout = QHBoxLayout()
        self.mode_group = QButtonGroup()
        for mode in ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']:
            radio = QRadioButton(mode)
            mode_layout.addWidget(radio)
            self.mode_group.addButton(radio)
        self.mode_group.buttons()[1].setChecked(True)  # CBC 기본 선택
        mode_group.setLayout(mode_layout)
        right_layout.addWidget(mode_group)

        # 송신자 패스워드 입력
        sender_password_layout = QHBoxLayout()
        sender_password_layout.addWidget(QLabel('송신자 패스워드:'))
        self.sender_password_input = QLineEdit()
        sender_password_layout.addWidget(self.sender_password_input)
        right_layout.addLayout(sender_password_layout)

        # 평문 입력
        right_layout.addWidget(QLabel('평문:'))
        self.plaintext_input = QTextEdit()
        self.plaintext_input.setPlainText("AES 암호화 테스트")
        right_layout.addWidget(self.plaintext_input)

        # 암호화 버튼 (송신자)
        self.encrypt_button = QPushButton('암호화 (송신)')
        self.encrypt_button.clicked.connect(self.encrypt)
        right_layout.addWidget(self.encrypt_button)

        # JSON 메시지 출력
        right_layout.addWidget(QLabel('JSON 메시지:'))
        self.json_message_output = QTextEdit()
        self.json_message_output.setReadOnly(True)
        right_layout.addWidget(self.json_message_output)

        # 인코딩된 메시지 출력
        right_layout.addWidget(QLabel('인코딩된 메시지:'))
        self.encoded_message_output = QTextEdit()
        self.encoded_message_output.setReadOnly(True)
        right_layout.addWidget(self.encoded_message_output)

        # 수신자 패스워드 입력
        receiver_password_layout = QHBoxLayout()
        receiver_password_layout.addWidget(QLabel('수신자 패스워드:'))
        self.receiver_password_input = QLineEdit()
        receiver_password_layout.addWidget(self.receiver_password_input)
        right_layout.addLayout(receiver_password_layout)

        # 복호화 버튼 (수신자)
        self.decrypt_button = QPushButton('복호화 (수신)')
        self.decrypt_button.clicked.connect(self.decrypt)
        right_layout.addWidget(self.decrypt_button)

        # 복호화된 텍스트 출력
        right_layout.addWidget(QLabel('복호화된 텍스트:'))
        self.decrypted_output = QTextEdit()
        self.decrypted_output.setReadOnly(True)
        right_layout.addWidget(self.decrypted_output)

        right_widget.setLayout(right_layout)

        # 좌우 위젯을 스플리터로 나누기
        splitter = QSplitter()
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([400, 600])  # 좌우 위젯의 초기 크기 설정

        main_layout.addWidget(splitter)
        self.setLayout(main_layout)

        self.setWindowTitle('AES 암호화/복호화 시뮬레이션')
        self.setGeometry(100, 100, 1200, 800)
        self.show()

    def get_key(self, password, salt, iterations):
        key_length = int(self.key_length_group.checkedButton().text()) // 8
        return PBKDF2(password, salt, dkLen=key_length, count=iterations)

    def encrypt(self):
        password = self.sender_password_input.text()
        if not password:
            self.json_message_output.setPlainText("오류: 송신자 패스워드를 입력하세요.")
            self.encoded_message_output.setPlainText("오류: 송신자 패스워드를 입력하세요.")
            return

        plaintext = self.plaintext_input.toPlainText().encode('utf-8')
        mode = self.mode_group.checkedButton().text()

        # PBKDF2 파라미터 생성
        salt = get_random_bytes(16)
        iterations = 100000

        # 키 생성
        key = self.get_key(password, salt, iterations)

        # 암호화 파라미터 및 암호화
        if mode == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
            params = {}
        elif mode in ['CBC', 'CFB', 'OFB']:
            iv = get_random_bytes(16)
            cipher = AES.new(key, getattr(AES, f'MODE_{mode}'), iv)
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
            params = {'iv': base64.b64encode(iv).decode('utf-8')}
        elif mode == 'CTR':
            nonce = get_random_bytes(8)
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
            ciphertext = cipher.encrypt(plaintext)  # CTR 모드는 패딩이 필요 없음
            params = {'nonce': base64.b64encode(nonce).decode('utf-8')}

        # 메시지 구성
        message = {
            'mode': mode,
            'salt': base64.b64encode(salt).decode('utf-8'),
            'iterations': iterations,
            'params': params,
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }

        # JSON 메시지 출력
        self.json_message_output.setPlainText(json.dumps(message, indent=2))

        # 메시지 인코딩 및 출력
        encoded_message = base64.b64encode(json.dumps(message).encode('utf-8')).decode('utf-8')
        self.encoded_message_output.setPlainText(encoded_message)

    def decrypt(self):
        try:
            password = self.receiver_password_input.text()
            if not password:
                self.decrypted_output.setPlainText("오류: 수신자 패스워드를 입력하세요.")
                return

            encoded_message = self.encoded_message_output.toPlainText()
            message = json.loads(base64.b64decode(encoded_message).decode('utf-8'))

            mode = message['mode']
            salt = base64.b64decode(message['salt'])
            iterations = message['iterations']
            ciphertext = base64.b64decode(message['ciphertext'])

            key = self.get_key(password, salt, iterations)

            if mode == 'ECB':
                cipher = AES.new(key, AES.MODE_ECB)
                decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            elif mode in ['CBC', 'CFB', 'OFB']:
                iv = base64.b64decode(message['params']['iv'])
                cipher = AES.new(key, getattr(AES, f'MODE_{mode}'), iv)
                decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            elif mode == 'CTR':
                nonce = base64.b64decode(message['params']['nonce'])
                cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
                decrypted = cipher.decrypt(ciphertext)

            self.decrypted_output.setPlainText(decrypted.decode('utf-8'))
        except ValueError as e:
            self.decrypted_output.setPlainText("복호화 실패: 잘못된 패스워드 또는 손상된 데이터")
        except Exception as e:
            self.decrypted_output.setPlainText(f"복호화 오류: {str(e)}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = EncryptionApp()
    sys.exit(app.exec_())
