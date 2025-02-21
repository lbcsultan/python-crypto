import sys
import os
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QTextEdit, QGridLayout, QPushButton, QGroupBox, QFileDialog, QCheckBox
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from Cryptodome.Hash import HMAC, MD5, SHA1, SHA256

class MACApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # MAC 소개
        intro_group = QGroupBox("메시지 인증 코드(MAC) 소개")
        intro_layout = QVBoxLayout()
        intro_text = QLabel(
            "메시지 인증 코드(MAC)는 메시지의 무결성과 인증을 제공하는 짧은 정보입니다. "
            "메시지와 비밀 키를 입력으로 사용하며, 메시지의 변조 여부를 확인할 수 있습니다. "
            "이 프로그램은 HMAC-MD5, HMAC-SHA1, HMAC-SHA256을 지원합니다."
        )
        intro_text.setWordWrap(True)
        intro_layout.addWidget(intro_text)
        intro_group.setLayout(intro_layout)
        layout.addWidget(intro_group)

        # 입력 방식 선택
        input_type_layout = QHBoxLayout()
        self.text_input_check = QCheckBox("텍스트 입력")
        self.file_input_check = QCheckBox("파일 입력")
        self.text_input_check.setChecked(True)
        input_type_layout.addWidget(self.text_input_check)
        input_type_layout.addWidget(self.file_input_check)
        layout.addLayout(input_type_layout)

        # 텍스트 입력 필드
        self.text_input_layout = QHBoxLayout()
        text_label = QLabel('텍스트:')
        self.text_field = QLineEdit()
        self.text_field.textChanged.connect(self.update_mac)
        clear_text_button = QPushButton('지우기')
        clear_text_button.clicked.connect(self.clear_text_input)
        self.text_input_layout.addWidget(text_label)
        self.text_input_layout.addWidget(self.text_field)
        self.text_input_layout.addWidget(clear_text_button)
        layout.addLayout(self.text_input_layout)

        # 파일 선택 필드
        self.file_input_layout = QHBoxLayout()
        file_label = QLabel('파일:')
        self.file_path = QLineEdit()
        self.file_path.setReadOnly(True)
        self.file_path.setStyleSheet("background-color: white;")
        file_button = QPushButton('파일 선택')
        file_button.clicked.connect(self.select_file)
        cancel_file_button = QPushButton('취소')
        cancel_file_button.clicked.connect(self.cancel_file_selection)
        self.file_input_layout.addWidget(file_label)
        self.file_input_layout.addWidget(self.file_path)
        self.file_input_layout.addWidget(file_button)
        self.file_input_layout.addWidget(cancel_file_button)
        layout.addLayout(self.file_input_layout)

        # 키 입력 필드와 랜덤 키 생성 버튼
        key_layout = QHBoxLayout()
        key_label = QLabel('비밀 키:')
        self.key_field = QLineEdit()
        self.key_field.textChanged.connect(self.update_mac)
        random_key_button = QPushButton('랜덤 키 생성')
        random_key_button.clicked.connect(self.generate_random_key)
        clear_key_button = QPushButton('지우기')
        clear_key_button.clicked.connect(self.clear_key)
        key_layout.addWidget(key_label)
        key_layout.addWidget(self.key_field)
        key_layout.addWidget(random_key_button)
        key_layout.addWidget(clear_key_button)
        layout.addLayout(key_layout)

        # MAC 결과 표시 영역
        self.mac_results = {}
        mac_layout = QGridLayout()
        for i, algo in enumerate(['HMAC-MD5', 'HMAC-SHA1', 'HMAC-SHA256']):
            label = QLabel(f'{algo}')
            label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            result = QTextEdit()
            result.setReadOnly(True)
            result.setFixedHeight(40)
            result.setLineWrapMode(QTextEdit.NoWrap)
            mac_layout.addWidget(label, i, 0)
            mac_layout.addWidget(result, i, 1)
            self.mac_results[algo] = result
        layout.addLayout(mac_layout)

        self.setLayout(layout)
        self.setWindowTitle('메시지 인증 코드(MAC) 테스터')
        self.setGeometry(300, 300, 1000, 500)

        # 체크박스 상태 변경 시 입력 필드 활성화/비활성화
        self.text_input_check.stateChanged.connect(self.toggle_input_fields)
        self.file_input_check.stateChanged.connect(self.toggle_input_fields)
        self.toggle_input_fields()

        # 초기 랜덤 키 생성
        self.generate_random_key()

        self.show()

    def toggle_input_fields(self):
        self.text_field.setEnabled(self.text_input_check.isChecked())
        self.file_path.setEnabled(self.file_input_check.isChecked())
        self.update_mac()

    def generate_random_key(self):
        random_key = os.urandom(16).hex()  # 16 바이트 (128 비트) 랜덤 키 생성
        self.key_field.setText(random_key)

    def clear_text_input(self):
        self.text_field.clear()

    def clear_key(self):
        self.key_field.clear()

    def select_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "파일 선택")
        if file_name:
            self.file_path.setText(file_name)
            self.update_mac()

    def cancel_file_selection(self):
        self.file_path.clear()
        self.update_mac()

    def update_mac(self):
        key = self.key_field.text().encode('utf-8')
        text_input = self.text_field.text().encode('utf-8') if self.text_input_check.isChecked() else b''
        file_input = self.file_path.text() if self.file_input_check.isChecked() else ''

        if not key or (not text_input and not file_input):
            for result in self.mac_results.values():
                result.clear()
            return

        message = text_input
        if file_input:
            try:
                with open(file_input, 'rb') as file:
                    message += file.read()
            except IOError:
                for result in self.mac_results.values():
                    result.setText("파일을 읽을 수 없습니다.")
                return

        algorithms = {
            'HMAC-MD5': MD5,
            'HMAC-SHA1': SHA1,
            'HMAC-SHA256': SHA256
        }

        for algo_name, algo in algorithms.items():
            h = HMAC.new(key, digestmod=algo)
            h.update(message)
            self.mac_results[algo_name].setText(h.hexdigest())

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = MACApp()
    sys.exit(app.exec_())
