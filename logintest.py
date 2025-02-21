import sys
import bcrypt
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QGroupBox, QGridLayout
from PyQt5.QtCore import Qt

class PasswordHashApp(QWidget):
    def __init__(self):
        super().__init__()
        self.users = {}  # 간단한 사용자 데이터베이스 (실제 앱에서는 데이터베이스를 사용해야 합니다)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # 사용자 등록 그룹
        register_group = QGroupBox("사용자 등록")
        register_layout = QGridLayout()
        
        register_layout.addWidget(QLabel("ID", alignment=Qt.AlignRight), 0, 0)
        self.register_username = QLineEdit()
        register_layout.addWidget(self.register_username, 0, 1)
        
        register_layout.addWidget(QLabel("Password", alignment=Qt.AlignRight), 1, 0)
        self.register_password1 = QLineEdit()
        self.register_password1.setEchoMode(QLineEdit.Password)
        register_layout.addWidget(self.register_password1, 1, 1)
        
        register_layout.addWidget(QLabel("Confirm Pass", alignment=Qt.AlignRight), 2, 0)
        self.register_password2 = QLineEdit()
        self.register_password2.setEchoMode(QLineEdit.Password)
        register_layout.addWidget(self.register_password2, 2, 1)
        
        register_button = QPushButton('등록')
        register_button.clicked.connect(self.register_user)
        register_layout.addWidget(register_button, 3, 1)
        
        self.register_message = QLabel('')
        register_layout.addWidget(self.register_message, 4, 0, 1, 2)
        
        register_group.setLayout(register_layout)
        layout.addWidget(register_group)

        # 패스워드 해시 그룹
        hash_group = QGroupBox("패스워드 해시")
        hash_layout = QVBoxLayout()
        self.hash_display = QLineEdit()
        self.hash_display.setReadOnly(True)
        hash_layout.addWidget(self.hash_display)
        hash_group.setLayout(hash_layout)
        layout.addWidget(hash_group)

        # 로그인 그룹
        login_group = QGroupBox("로그인")
        login_layout = QGridLayout()
        
        login_layout.addWidget(QLabel("ID", alignment=Qt.AlignRight), 0, 0)
        self.login_username = QLineEdit()
        login_layout.addWidget(self.login_username, 0, 1)
        
        login_layout.addWidget(QLabel("Password", alignment=Qt.AlignRight), 1, 0)
        self.login_password = QLineEdit()
        self.login_password.setEchoMode(QLineEdit.Password)
        login_layout.addWidget(self.login_password, 1, 1)
        
        login_button = QPushButton('로그인')
        login_button.clicked.connect(self.login_user)
        login_layout.addWidget(login_button, 2, 1)
        
        self.login_message = QLabel('')
        login_layout.addWidget(self.login_message, 3, 0, 1, 2)
        
        login_group.setLayout(login_layout)
        layout.addWidget(login_group)

        self.setLayout(layout)
        self.setWindowTitle('패스워드해시 테스터')
        self.setGeometry(300, 300, 800, 500)  # 윈도우 폭을 800으로 늘렸습니다

    def register_user(self):
        username = self.register_username.text()
        password1 = self.register_password1.text()
        password2 = self.register_password2.text()
        
        if not username or not password1 or not password2:
            self.register_message.setText('모든 필드를 입력해주세요.')
            self.register_message.setStyleSheet('color: red')
            return
        
        if password1 != password2:
            self.register_message.setText('비밀번호가 일치하지 않습니다.')
            self.register_message.setStyleSheet('color: red')
            return
        
        # 비밀번호를 해시화하여 저장
        hashed = bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt())
        self.users[username] = hashed
        
        # 해시값을 화면에 표시
        self.hash_display.setText(hashed.decode('utf-8'))
        
        self.register_message.setText('사용자가 등록되었습니다.')
        self.register_message.setStyleSheet('color: green')

    def login_user(self):
        username = self.login_username.text()
        password = self.login_password.text()
        
        if username in self.users:
            # 저장된 해시와 입력된 비밀번호 비교
            if bcrypt.checkpw(password.encode('utf-8'), self.users[username]):
                self.login_message.setText('로그인에 성공했습니다.')
                self.login_message.setStyleSheet('color: green')
            else:
                self.login_message.setText('비밀번호가 일치하지 않습니다.')
                self.login_message.setStyleSheet('color: red')
        else:
            self.login_message.setText('존재하지 않는 사용자입니다.')
            self.login_message.setStyleSheet('color: red')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PasswordHashApp()
    ex.show()
    sys.exit(app.exec_())
