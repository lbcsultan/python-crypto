import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QTextEdit, QGridLayout, QPushButton, QFileDialog, QCheckBox, QGroupBox
from PyQt5.QtCore import Qt
from Crypto.Hash import MD5, SHA1, SHA224, SHA256, SHA384, SHA512

class HashApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # 해시 함수 소개
        intro_group = QGroupBox("해시 함수 소개")
        intro_layout = QVBoxLayout()
        intro_text = QLabel(
            "해시 함수는 임의의 길이의 데이터를 고정된 길이의 데이터로 매핑하는 함수입니다.\n"
            "주요 특징:\n"
            "1. 같은 입력에 대해 항상 같은 출력을 생성합니다.\n"
            "2. 출력값으로부터 입력값을 유추하기 어렵습니다.\n"
            "3. 작은 입력 변화에도 출력값이 크게 변합니다.\n"
            "이 프로그램은 MD5, SHA1, SHA224, SHA256, SHA384, SHA512 해시 함수를 지원합니다."
        )
        intro_text.setWordWrap(True)
        intro_layout.addWidget(intro_text)
        intro_group.setLayout(intro_layout)
        layout.addWidget(intro_group)

        # 텍스트 입력 필드와 지우기 버튼
        input_layout = QHBoxLayout()
        input_label = QLabel('텍스트 입력:')
        self.input_field = QLineEdit()
        self.input_field.textChanged.connect(self.update_hashes)
        clear_button = QPushButton('지우기')
        clear_button.clicked.connect(self.clear_text_input)
        input_layout.addWidget(input_label)
        input_layout.addWidget(self.input_field)
        input_layout.addWidget(clear_button)
        layout.addLayout(input_layout)

        # 파일 선택 버튼
        file_layout = QHBoxLayout()
        file_label = QLabel('파일 선택:')
        self.file_path = QLineEdit()
        self.file_path.setReadOnly(True)
        file_button = QPushButton('파일 선택')
        file_button.clicked.connect(self.select_file)
        cancel_button = QPushButton('취소')
        cancel_button.clicked.connect(self.cancel_file_selection)
        file_layout.addWidget(file_label)
        file_layout.addWidget(self.file_path)
        file_layout.addWidget(file_button)
        file_layout.addWidget(cancel_button)
        layout.addLayout(file_layout)

        # 입력 선택 체크박스
        checkbox_layout = QHBoxLayout()
        self.text_checkbox = QCheckBox('텍스트 입력 사용')
        self.file_checkbox = QCheckBox('파일 입력 사용')
        self.text_checkbox.setChecked(True)
        self.file_checkbox.setChecked(True)
        self.text_checkbox.stateChanged.connect(self.update_hashes)
        self.file_checkbox.stateChanged.connect(self.update_hashes)
        checkbox_layout.addWidget(self.text_checkbox)
        checkbox_layout.addWidget(self.file_checkbox)
        layout.addLayout(checkbox_layout)

        # 해시 결과 표시 영역
        hash_layout = QGridLayout()
        self.hash_results = {}
        self.hash_functions = [MD5, SHA1, SHA224, SHA256, SHA384, SHA512]

        for i, hash_func in enumerate(self.hash_functions):
            label = QLabel(f"{hash_func.__name__}")
            label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            result = QTextEdit()
            result.setReadOnly(True)
            result.setFixedHeight(40)
            result.setLineWrapMode(QTextEdit.NoWrap)
            result.setAlignment(Qt.AlignLeft)
            hash_layout.addWidget(label, i, 0)
            hash_layout.addWidget(result, i, 1)
            self.hash_results[hash_func.__name__] = result

        layout.addLayout(hash_layout)

        self.setLayout(layout)
        self.setWindowTitle('해시 함수 테스터')
        self.setGeometry(300, 300, 1500, 600)  # 높이를 600으로 증가
        self.show()

    def clear_text_input(self):
        self.input_field.clear()
        self.update_hashes()

    def update_hashes(self):
        if not self.text_checkbox.isChecked() and not self.file_checkbox.isChecked():
            self.clear_hash_results()
            return

        data = b''
        if self.text_checkbox.isChecked():
            data += self.input_field.text().encode('utf-8')
        if self.file_checkbox.isChecked() and self.file_path.text():
            try:
                with open(self.file_path.text(), 'rb') as file:
                    data += file.read()
            except IOError:
                for result in self.hash_results.values():
                    result.setText("파일을 읽을 수 없습니다.")
                return

        if data:
            self.calculate_hashes(data)
        else:
            self.clear_hash_results()

    def select_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "파일 선택")
        if file_name:
            self.file_path.setText(file_name)
            self.update_hashes()

    def cancel_file_selection(self):
        self.file_path.clear()
        self.update_hashes()

    def clear_hash_results(self):
        for result in self.hash_results.values():
            result.clear()

    def calculate_hashes(self, data):
        for hash_func in self.hash_functions:
            h = hash_func.new()
            h.update(data)
            self.hash_results[hash_func.__name__].setText(h.hexdigest())

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = HashApp()
    sys.exit(app.exec_())
