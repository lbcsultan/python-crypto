import sys
import json
import base64
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QGroupBox, QMessageBox
)
from PyQt6.QtCore import Qt

# PyCryptodome 라이브러리 임포트
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pss
from Cryptodome.Random import get_random_bytes

# --- Base64 인코딩/디코딩 헬퍼 함수 ---
# PyCryptodome의 바이너리 데이터를 JSON에 저장하기 위해 문자열로 변환하는 데 사용
def b_to_b64s(b: bytes) -> str:
    """Bytes를 Base64 문자열로 인코딩합니다."""
    return base64.b64encode(b).decode('utf-8')

def b64s_to_b(s: str) -> bytes:
    """Base64 문자열을 Bytes로 디코딩합니다."""
    return base64.b64decode(s.encode('utf-8'))

class ElectronicEnvelopeSimulator(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("전자 봉투 송수신 시뮬레이터 (단계별 출력)")
        self.setGeometry(100, 100, 1000, 800) # 창 크기 조정

        # 키 데이터 (PEM 형식의 문자열로 메모리에 저장)
        self.alice_private_key_pem = None
        self.alice_public_key_pem = None
        self.bob_private_key_pem = None
        self.bob_public_key_pem = None

        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()

        # 로그 출력 영역
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFixedHeight(150) # 로그 영역 높이 고정
        self.log_display.setStyleSheet("font-family: Consolas, 'Courier New', monospace; font-size: 11px; background-color: #f0f0f0;")
        main_layout.addWidget(QLabel("<h4>작업 로그:</h4>"))
        main_layout.addWidget(self.log_display)

        # 1. 키 쌍 생성 섹션
        key_gen_group = QGroupBox("1. 키 쌍 생성")
        key_gen_layout = QVBoxLayout()
        key_gen_buttons_layout = QHBoxLayout()

        btn_gen_alice = QPushButton("앨리스(송신자) 키 쌍 생성")
        btn_gen_alice.clicked.connect(self.generate_alice_keys)
        key_gen_buttons_layout.addWidget(btn_gen_alice)

        btn_gen_bob = QPushButton("밥(수신자) 키 쌍 생성")
        btn_gen_bob.clicked.connect(self.generate_bob_keys)
        key_gen_buttons_layout.addWidget(btn_gen_bob)

        key_gen_layout.addLayout(key_gen_buttons_layout)
        self.key_status_label = QLabel("키 상태: 생성되지 않음.")
        self.key_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.key_status_label.setStyleSheet("font-weight: bold; color: blue;")
        key_gen_layout.addWidget(self.key_status_label)
        key_gen_group.setLayout(key_gen_layout)
        main_layout.addWidget(key_gen_group)

        # 2. 송신자 (앨리스) 섹션
        sender_group = QGroupBox("2. 송신자 (앨리스) - 전자 봉투 생성")
        sender_layout = QVBoxLayout()
        sender_layout.addWidget(QLabel("① 보낼 원본 메시지:"))
        self.txt_sender_message = QTextEdit()
        self.txt_sender_message.setPlaceholderText("여기에 보낼 메시지를 입력하세요.")
        self.txt_sender_message.setText("안녕하세요, 앨리스가 밥에게 보내는 매우 중요한 비밀 메시지입니다. 이 메시지는 안전하게 전달되어야 합니다.")
        sender_layout.addWidget(self.txt_sender_message)

        btn_create_envelope = QPushButton("② 전자 봉투 생성")
        btn_create_envelope.clicked.connect(self.create_envelope_gui)
        sender_layout.addWidget(btn_create_envelope)

        sender_layout.addWidget(QLabel("③ 생성된 전자 봉투 (JSON 형식):"))
        self.txt_electronic_envelope_json = QTextEdit()
        self.txt_electronic_envelope_json.setReadOnly(True)
        self.txt_electronic_envelope_json.setPlaceholderText("전자 봉투 JSON이 여기에 표시됩니다.")
        sender_layout.addWidget(self.txt_electronic_envelope_json)
        sender_group.setLayout(sender_layout)
        main_layout.addWidget(sender_group)

        # 3. 수신자 (밥) 섹션
        receiver_group = QGroupBox("3. 수신자 (밥) - 전자 봉투 열기")
        receiver_layout = QVBoxLayout()
        receiver_layout.addWidget(QLabel("① 수신된 전자 봉투 (JSON):"))
        self.txt_receiver_envelope_json = QTextEdit()
        self.txt_receiver_envelope_json.setPlaceholderText("여기에 수신된 전자 봉투 JSON을 붙여넣으세요.")
        receiver_layout.addWidget(self.txt_receiver_envelope_json)

        btn_open_envelope = QPushButton("② 전자 봉투 열기 및 검증")
        btn_open_envelope.clicked.connect(self.open_envelope_gui)
        receiver_layout.addWidget(btn_open_envelope)

        receiver_layout.addWidget(QLabel("③ 복호화된 메시지:"))
        self.txt_decrypted_message = QTextEdit()
        self.txt_decrypted_message.setReadOnly(True)
        self.txt_decrypted_message.setPlaceholderText("복호화된 메시지가 여기에 표시됩니다.")
        self.txt_decrypted_message.setStyleSheet("background-color: #e0ffe0;")
        receiver_layout.addWidget(self.txt_decrypted_message)

        self.lbl_signature_status = QLabel("서명 검증 상태: 대기 중")
        self.lbl_signature_status.setStyleSheet("font-weight: bold; color: gray;")
        receiver_layout.addWidget(self.lbl_signature_status)
        receiver_group.setLayout(receiver_layout)
        main_layout.addWidget(receiver_group)

        self.setLayout(main_layout)
        self.log_message("시뮬레이터 시작. 각 단계별 버튼을 눌러보세요.")

    def log_message(self, message: str):
        """로그 메시지를 GUI 로그 영역에 추가합니다."""
        self.log_display.append(message)

    def update_key_status(self):
        """키 생성/로드 상태를 GUI에 업데이트합니다."""
        status_parts = []
        if self.alice_private_key_pem and self.alice_public_key_pem:
            status_parts.append("앨리스 키: 생성됨")
        else:
            status_parts.append("앨리스 키: 없음")

        if self.bob_private_key_pem and self.bob_public_key_pem:
            status_parts.append("밥 키: 생성됨")
        else:
            status_parts.append("밥 키: 없음")
        
        self.key_status_label.setText("키 상태: " + ", ".join(status_parts))

    def generate_rsa_key_pair(self, name: str):
        """RSA 키 쌍을 생성하고 해당 이름에 맞춰 저장합니다."""
        self.log_message(f"\n--- {name.capitalize()} 키 쌍 생성 시작 ---")
        try:
            key = RSA.generate(2048) # 2048비트 RSA 키 생성
            private_key_pem = key.export_key().decode('utf-8')
            public_key_pem = key.publickey().export_key().decode('utf-8')

            if name == "alice":
                self.alice_private_key_pem = private_key_pem
                self.alice_public_key_pem = public_key_pem
                self.log_message(f"앨리스 개인키 (PEM):\n{private_key_pem[:100]}...")
                self.log_message(f"앨리스 공개키 (PEM):\n{public_key_pem[:100]}...")
            elif name == "bob":
                self.bob_private_key_pem = private_key_pem
                self.bob_public_key_pem = public_key_pem
                self.log_message(f"밥 개인키 (PEM):\n{private_key_pem[:100]}...")
                self.log_message(f"밥 공개키 (PEM):\n{public_key_pem[:100]}...")
            
            self.log_message(f"{name.capitalize()} 키 쌍이 성공적으로 생성되어 메모리에 저장되었습니다.")
            QMessageBox.information(self, "키 생성", f"{name.capitalize()} 키 쌍이 성공적으로 생성되었습니다.")
            self.update_key_status()
        except Exception as e:
            self.log_message(f"오류: {name.capitalize()} 키 생성 중 오류 발생: {e}")
            QMessageBox.critical(self, "오류", f"{name.capitalize()} 키 생성 중 오류 발생: {e}")

    def generate_alice_keys(self):
        self.generate_rsa_key_pair("alice")

    def generate_bob_keys(self):
        self.generate_rsa_key_pair("bob")

    def create_envelope_gui(self):
        """GUI에서 송신자로부터 전자 봉투 생성을 트리거합니다."""
        self.log_message("\n--- 전자 봉투 생성 시작 ---")
        message = self.txt_sender_message.toPlainText()
        if not message:
            QMessageBox.warning(self, "경고", "보낼 메시지를 입력하세요.")
            self.log_message("오류: 보낼 메시지가 없습니다.")
            return
        
        # 키 존재 여부 확인
        if not self.alice_private_key_pem:
            QMessageBox.warning(self, "키 오류", "앨리스의 개인키가 필요합니다. 먼저 키를 생성하세요.")
            self.log_message("오류: 앨리스의 개인키가 없습니다.")
            return
        if not self.bob_public_key_pem:
            QMessageBox.warning(self, "키 오류", "밥의 공개키가 필요합니다. 먼저 키를 생성하세요.")
            self.log_message("오류: 밥의 공개키가 없습니다.")
            return

        message_bytes = message.encode('utf-8')
        self.log_message(f"1. 원본 메시지 (Bytes): {message_bytes[:50]}...")

        try:
            # 1. 메시지 서명 (송신자의 개인키로)
            self.log_message("2. 메시지에 서명 시작 (앨리스의 개인키 사용)...")
            h = SHA256.new(message_bytes)
            self.log_message(f"   - 메시지 SHA256 해시: {b_to_b64s(h.digest())[:50]}...")
            
            sender_private_key_obj = RSA.import_key(self.alice_private_key_pem)
            signer = pss.new(sender_private_key_obj)
            signature = signer.sign(h)
            self.log_message(f"   - 생성된 서명 (Base64): {b_to_b64s(signature)[:50]}...")

            # 2. 메시지 암호화 (세션 키로 AES-EAX 모드 사용)
            self.log_message("3. 메시지 암호화 시작 (AES-EAX 세션 키 사용)...")
            session_key = get_random_bytes(16)  # 128비트 AES 세션 키
            self.log_message(f"   - 생성된 세션 키 (Base64): {b_to_b64s(session_key)[:50]}...")

            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(message_bytes)
            nonce = cipher_aes.nonce
            
            self.log_message(f"   - 생성된 Nonce (Base64): {b_to_b64s(nonce)[:50]}...")
            self.log_message(f"   - 생성된 암호문 (Base64): {b_to_b64s(ciphertext)[:50]}...")
            self.log_message(f"   - 생성된 인증 태그 (Base64): {b_to_b64s(tag)[:50]}...")

            # 3. 세션 키 암호화 (수신자의 공개키로 RSA-OAEP 사용)
            self.log_message("4. 세션 키 암호화 시작 (밥의 공개키 사용)...")
            receiver_public_key_obj = RSA.import_key(self.bob_public_key_pem)
            cipher_rsa_public = PKCS1_OAEP.new(receiver_public_key_obj)
            encrypted_session_key = cipher_rsa_public.encrypt(session_key)
            self.log_message(f"   - 암호화된 세션 키 (Base64): {b_to_b64s(encrypted_session_key)[:50]}...")

            # 4. 전자 봉투 구성 (JSON)
            self.log_message("5. 모든 구성 요소를 JSON 전자 봉투로 통합...")
            envelope_data = {
                "encrypted_session_key": b_to_b64s(encrypted_session_key),
                "ciphertext": b_to_b64s(ciphertext),
                "nonce": b_to_b64s(nonce),
                "tag": b_to_b64s(tag),
                "signature": b_to_b64s(signature)
            }
            envelope_json = json.dumps(envelope_data, indent=4)
            self.log_message(f"   - 최종 전자 봉투 JSON:\n{envelope_json[:300]}...") # 일부만 출력
            
            self.txt_electronic_envelope_json.setText(envelope_json)
            # 수신자 텍스트 에디터에 자동으로 복사 (시뮬레이션 편의성)
            self.txt_receiver_envelope_json.setText(envelope_json) 
            QMessageBox.information(self, "성공", "전자 봉투가 성공적으로 생성되었습니다!")
            self.log_message("--- 전자 봉투 생성 완료 ---")

        except Exception as e:
            self.log_message(f"오류: 전자 봉투 생성 중 치명적인 오류 발생: {e}")
            QMessageBox.critical(self, "오류", f"전자 봉투 생성에 실패했습니다: {e}")

    def open_envelope_gui(self):
        """GUI에서 수신자로부터 전자 봉투 열기 및 검증을 트리거합니다."""
        self.log_message("\n--- 전자 봉투 열기 및 검증 시작 ---")
        envelope_json_str = self.txt_receiver_envelope_json.toPlainText()
        if not envelope_json_str:
            QMessageBox.warning(self, "경고", "열 전자 봉투 (JSON)를 입력하거나 붙여넣으세요.")
            self.log_message("오류: 열 전자 봉투 JSON이 비어 있습니다.")
            return

        # 키 존재 여부 확인
        if not self.bob_private_key_pem:
            QMessageBox.warning(self, "키 오류", "밥의 개인키가 필요합니다. 먼저 키를 생성하세요.")
            self.log_message("오류: 밥의 개인키가 없습니다.")
            return
        if not self.alice_public_key_pem:
            QMessageBox.warning(self, "키 오류", "앨리스의 공개키가 필요합니다. 먼저 키를 생성하세요.")
            self.log_message("오류: 앨리스의 공개키가 없습니다.")
            return

        try:
            self.log_message("1. 전자 봉투 JSON 파싱 및 Base64 디코딩...")
            envelope_data = json.loads(envelope_json_str)

            # Base64 디코딩
            encrypted_session_key = b64s_to_b(envelope_data["encrypted_session_key"])
            ciphertext = b64s_to_b(envelope_data["ciphertext"])
            nonce = b64s_to_b(envelope_data["nonce"])
            tag = b64s_to_b(envelope_data["tag"])
            signature = b64s_to_b(envelope_data["signature"])

            self.log_message(f"   - 암호화된 세션 키 (Base64): {b_to_b64s(encrypted_session_key)[:50]}...")
            self.log_message(f"   - 암호문 (Base64): {b_to_b64s(ciphertext)[:50]}...")
            self.log_message(f"   - Nonce (Base64): {b_to_b64s(nonce)[:50]}...")
            self.log_message(f"   - Tag (Base64): {b_to_b64s(tag)[:50]}...")
            self.log_message(f"   - 서명 (Base64): {b_to_b64s(signature)[:50]}...")


            # 2. 세션 키 복호화 (수신자의 개인키로)
            self.log_message("3. 세션 키 복호화 시작 (밥의 개인키 사용)...")
            receiver_private_key_obj = RSA.import_key(self.bob_private_key_pem)
            cipher_rsa_private = PKCS1_OAEP.new(receiver_private_key_obj)
            session_key = cipher_rsa_private.decrypt(encrypted_session_key)
            self.log_message(f"   - 복호화된 세션 키 (Base64): {b_to_b64s(session_key)[:50]}...")

            # 3. 메시지 복호화 (세션 키로 AES-EAX 모드 사용)
            self.log_message("4. 메시지 복호화 및 인증 태그 검증 시작 (세션 키 사용)...")
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
            decrypted_message_bytes = cipher_aes.decrypt_and_verify(ciphertext, tag) # 복호화와 태그 검증 동시 수행
            decrypted_message = decrypted_message_bytes.decode('utf-8')
            self.log_message(f"   - 복호화된 메시지 (UTF-8): {decrypted_message}")

            # 4. 서명 검증 (송신자의 공개키로)
            self.log_message("5. 서명 검증 시작 (앨리스의 공개키 사용)...")
            h = SHA256.new(decrypted_message_bytes) # 복호화된 메시지의 해시값을 다시 계산
            self.log_message(f"   - 복호화된 메시지 SHA256 해시: {b_to_b64s(h.digest())[:50]}...")

            sender_public_key_obj = RSA.import_key(self.alice_public_key_pem)
            verifier = pss.new(sender_public_key_obj)
            
            signature_status_text = ""
            try:
                verifier.verify(h, signature)
                signature_status_text = "✅ 서명 유효함: 메시지가 송신자로부터 왔고, 위변조되지 않았습니다."
                self.log_message("   - 서명 검증 성공!")
            except (ValueError, TypeError) as e:
                signature_status_text = f"❌ 서명 유효하지 않음: 메시지가 위변조되었거나, 송신자의 서명이 아닙니다. ({e})"
                self.log_message(f"   - 서명 검증 실패: {e}")

            self.txt_decrypted_message.setText(decrypted_message)
            self.lbl_signature_status.setText(f"서명 검증 상태: {signature_status_text}")
            
            if "유효함" in signature_status_text:
                self.lbl_signature_status.setStyleSheet("font-weight: bold; color: green;")
                QMessageBox.information(self, "성공", "전자 봉투가 성공적으로 열리고 서명이 유효합니다!")
            else:
                self.lbl_signature_status.setStyleSheet("font-weight: bold; color: orange;") # 서명은 유효하지 않지만 메시지는 복호화
                QMessageBox.warning(self, "경고", f"전자 봉투는 열렸으나, 서명은 {signature_status_text}합니다.")
            self.log_message("--- 전자 봉투 열기 및 검증 완료 ---")

        except json.JSONDecodeError:
            error_message = "오류: 유효하지 않은 JSON 형식입니다. 전자 봉투 형식을 확인하세요."
            self.log_message(error_message)
            self.txt_decrypted_message.clear()
            self.lbl_signature_status.setText("서명 검증 상태: 오류 (JSON 형식)")
            self.lbl_signature_status.setStyleSheet("font-weight: bold; color: red;")
            QMessageBox.critical(self, "오류", error_message)
        except Exception as e:
            error_message = f"전자 봉투 열기 중 치명적인 오류 발생: {e}\n(잘못된 키, 메시지 변조 등으로 인해 발생할 수 있습니다.)"
            self.log_message(f"오류: {error_message}")
            self.txt_decrypted_message.clear()
            self.lbl_signature_status.setText("서명 검증 상태: 오류 발생")
            self.lbl_signature_status.setStyleSheet("font-weight: bold; color: red;")
            QMessageBox.critical(self, "오류", error_message)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = ElectronicEnvelopeSimulator()
    ex.show()
    sys.exit(app.exec())