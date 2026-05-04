import sys
from PyQt5.QtWidgets import QApplication, QWidget, QMessageBox, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QFileDialog, QCheckBox, QFrame
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIntValidator
import code_steganography as video_steg  # алгоритм


video_file_path = ""  ### путь к файлу видео
photo_file_path = ""  ### путь к файлу изображения


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Encode-Decode Window")
        self.resize(1200, 400)

        # Создание макета
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)  # При необходимости отрегулировать поля

        # шаг 1: выбор файла видео
        video_layout = QHBoxLayout()
        video_label = QLabel("Choose Video File:")
        self.video_input = QLineEdit()
        video_button = QPushButton("Browse")
        video_button.clicked.connect(lambda: self.open_video_file(self.video_input))
        video_layout.addWidget(video_label)
        video_layout.addWidget(self.video_input)
        video_layout.addWidget(video_button)
        layout.addLayout(video_layout)

        # шаг 2: выбор файла изображения
        photo_layout = QHBoxLayout()
        photo_label = QLabel("Choose Photo File:")
        self.photo_input = QLineEdit()
        photo_button = QPushButton("Browse")
        photo_button.clicked.connect(lambda: self.open_photo_file(self.photo_input))
        photo_layout.addWidget(photo_label)
        photo_layout.addWidget(self.photo_input)
        photo_layout.addWidget(photo_button)
        layout.addLayout(photo_layout)

        # Разделение окна на две половины
        split_layout = QHBoxLayout()


        ############################### первая часть: шифрование
        encode_layout = QVBoxLayout()
        encode_title = QLabel("<p align=\"center\"><span style=\"font-size:20pt; font-weight:600; color:#5500ff;\">Encode</span></p>")
        encode_title.setAlignment(Qt.AlignCenter)
        encode_layout.addWidget(encode_title)
        encode_layout.setAlignment(Qt.AlignTop)
        
        # Пароль для кадров видео (для их перемешивания)
        password_layout1 = QHBoxLayout()
        password_label1 = QLabel("Password Video Frames:")
        self.password_input1 = QLineEdit()
        self.password_input1.setValidator(QIntValidator())  ### разрешать только числа
        self.password_input1.setEchoMode(QLineEdit.Password)
        show_password_checkbox1 = QCheckBox("Show")
        show_password_checkbox1.stateChanged.connect(lambda state, pw=self.password_input1: self.show_password(state, pw))
        password_layout1.addWidget(password_label1)
        password_layout1.addWidget(self.password_input1)
        password_layout1.addWidget(show_password_checkbox1)
        encode_layout.addLayout(password_layout1)
        
        # Пароль для скрытия изображения (для его перемешивания)
        password_layout2 = QHBoxLayout()
        password_label2 = QLabel("Password Hidden Photo:")
        self.password_input2 = QLineEdit()
        self.password_input2.setValidator(QIntValidator())  ### разрешать только числа
        self.password_input2.setEchoMode(QLineEdit.Password)
        show_password_checkbox2 = QCheckBox("Show")
        show_password_checkbox2.stateChanged.connect(lambda state, pw=self.password_input2: self.show_password(state, pw))
        password_layout2.addWidget(password_label2)
        password_layout2.addWidget(self.password_input2)
        password_layout2.addWidget(show_password_checkbox2)
        encode_layout.addLayout(password_layout2)
        
        # Пароль для AES -> Данные, которые будут скрыты внутри аудиоканала (шифрование)
        password_layout3 = QHBoxLayout()
        password_label3 = QLabel("Password Audio Data:")
        self.password_input3 = QLineEdit()
        self.password_input3.setEchoMode(QLineEdit.Password)
        show_password_checkbox3 = QCheckBox("Show")
        show_password_checkbox3.stateChanged.connect(lambda state, pw=self.password_input3: self.show_password(state, pw))
        password_layout3.addWidget(password_label3)
        password_layout3.addWidget(self.password_input3)
        password_layout3.addWidget(show_password_checkbox3)
        encode_layout.addLayout(password_layout3)
        

        # Кнопка шифрования
        encode_button = QPushButton("Encode")
        encode_button.setFixedSize(100, 30)
        encode_button_layout = QHBoxLayout()
        encode_button_layout.addWidget(encode_button)
        encode_button_layout.setAlignment(Qt.AlignCenter)
        encode_layout.addLayout(encode_button_layout)
        split_layout.addLayout(encode_layout)
        # Соединение сигнала нажатия кнопки кодирования с соответствующей функцией
        encode_button.clicked.connect(lambda: self.encode())


        # Проведение вертикальной линии между половинками
        line = QFrame()
        line.setFrameShape(QFrame.VLine)
        line.setFrameShadow(QFrame.Sunken)
        split_layout.addWidget(line)


        ###############################  часть 2: декодирование
        decode_layout = QVBoxLayout()
        decode_title = QLabel("<p align=\"center\"><span style=\"font-size:20pt; font-weight:600; color:#5500ff;\">Decode</span></p>")
        decode_title.setAlignment(Qt.AlignCenter)
        decode_layout.addWidget(decode_title)
        decode_layout.setAlignment(Qt.AlignTop)
        
        # Пароль для AES -> Скрытые аудиоданные, подлежащие извлечению
        password_layout4 = QHBoxLayout()
        password_label4 = QLabel("Password Audio Data:")
        self.password_input4 = QLineEdit()
        self.password_input4.setEchoMode(QLineEdit.Password)
        show_password_checkbox4 = QCheckBox("Show")
        show_password_checkbox4.stateChanged.connect(lambda state, pw=self.password_input4: self.show_password(state, pw))
        password_layout4.addWidget(password_label4)
        password_layout4.addWidget(self.password_input4)
        password_layout4.addWidget(show_password_checkbox4)
        decode_layout.addLayout(password_layout4)
        
        # Длина скрытых данных в аудио
        password_layout5 = QHBoxLayout()
        password_label5 = QLabel("Length Audio Data:")
        self.password_input5 = QLineEdit()
        self.password_input5.setValidator(QIntValidator())  ### to allow only numbers
        self.password_input5.setEchoMode(QLineEdit.Password)
        show_password_checkbox5 = QCheckBox("Show")
        show_password_checkbox5.stateChanged.connect(lambda state, pw=self.password_input5: self.show_password(state, pw))
        password_layout5.addWidget(password_label5)
        password_layout5.addWidget(self.password_input5)
        password_layout5.addWidget(show_password_checkbox5)
        decode_layout.addLayout(password_layout5)
        
    
        # кнопка декодирования
        decode_button = QPushButton("Decode")
        decode_button.setFixedSize(100, 30)
        decode_button_layout = QHBoxLayout()
        decode_button_layout.addWidget(decode_button)
        decode_button_layout.setAlignment(Qt.AlignCenter)
        decode_layout.addLayout(decode_button_layout)
        split_layout.addLayout(decode_layout)
        # Соединение сигнала нажатия кнопки декодирования с соответствующей функцией
        decode_button.clicked.connect(lambda: self.decode())


        split_layout.addLayout(decode_layout)
        layout.addLayout(split_layout)
        self.setLayout(layout)


    ### Кнопка "Обзор" для файла видео
    def open_video_file(self, line_edit):
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setNameFilter("Video Files (*.mp4 *.avi *.mkv)")
        global video_file_path
        if file_dialog.exec_():
            video_file_path = file_dialog.selectedFiles()[0]
            line_edit.setText(video_file_path)
    
    
    ### Кнопка "Обзор" для файла изображения
    def open_photo_file(self, line_edit):
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setNameFilter("Photo Files (*.png)")
        global photo_file_path
        if file_dialog.exec_():
            photo_file_path = file_dialog.selectedFiles()[0]
            line_edit.setText(photo_file_path)


    ### Кнопка переключения видимости пароля
    def show_password(self, state, line_edit):
        if state == Qt.Checked:
            line_edit.setEchoMode(QLineEdit.Normal)
        else:
            line_edit.setEchoMode(QLineEdit.Password)
    
    
    ### Функция для отображения сообщения/ошибки/информации
    def display_msg(self, title, msg, ico_type=None):
        MsgBox = QMessageBox()
        MsgBox.setText(msg)
        MsgBox.setWindowTitle(title)
        if ico_type == 'err':
            ico =QMessageBox.Critical
        else:
            ico = QMessageBox.Information
        MsgBox.setIcon(ico)
        MsgBox.exec()
    
    
    ### Функция для отображения диалогового окна сохранения файла (стего-видео)
    def save_file_video(self):
        output_path = QFileDialog.getSaveFileName(None, 'Save encoded video file', '', "AVI File(*.avi)")[0]
        return output_path
    
    
    ### Функция для отображения диалогового окна сохранения файла (изображение получено)
    def save_file_photo(self):
        output_path = QFileDialog.getSaveFileName(None, 'Save decoded photo file', '', "PNG File(*.png)")[0]
        return output_path
    
    
    ### Функция, скрывающая информацию внутри видео
    def encode(self):
        global video_file_path
        global photo_file_path
        
        # проверки, есть ли всё необходимое для процесса кодирования
        if video_file_path == "":
            self.display_msg('Error: No file chosen', 'You must select input video file!', 'err')
        elif photo_file_path == "":
            self.display_msg('Error: No file chosen', 'You must select input photo file!', 'err')
        elif self.password_input1.text() == "":
            self.display_msg('Error: No key chosen', 'You must select the key for the video file!', 'err')
        elif self.password_input2.text() == "":
            self.display_msg('Error: No key chosen', 'You must select the key for the image file!', 'err')
        elif self.password_input3.text() == "":
            self.display_msg('Error: No password chosen', 'You must select the password for the audio!', 'err')
        elif len(self.password_input3.text()) != 16:
            self.display_msg('Error: Wrong password length', 'The password must have 16 characters!', 'err')
        else:
            key1 = int(self.password_input1.text())
            key2 = int(self.password_input2.text())
            key3 = self.password_input3.text()
            
            output_path = self.save_file_video()
            if output_path == "":
                self.display_msg('Operation cancelled', 'Operation cancelled by user!')
            else:
                try:
                    video_steg.encode(video_file_path, photo_file_path, key1, key2, key3, output_path)
                except video_steg.FileError as fe:
                    self.display_msg('File Error', str(fe), 'err')
                except video_steg.DataError as de:
                    self.display_msg('Data Error', str(de), 'err')
                else:
                    self.video_input.clear()
                    self.photo_input.clear()
                    self.display_msg('Success', 'Encoded Successfully!\n\n')
    
    
    ### Функция, которая декодирует информацию, содержащуюся в видео
    def decode(self):
        global video_file_path
        
        # проверки, есть ли всё необходимое для процесса декодирования
        if video_file_path == "":
            self.display_msg('Error: No file chosen', 'You must select input video file!', 'err')
        elif self.password_input4.text() == "":
            self.display_msg('Error: No password chosen', 'You must select the password for the audio!', 'err')
        elif len(self.password_input4.text()) != 16:
            self.display_msg('Error: Wrong password length', 'The password must have 16 characters!', 'err')
        elif self.password_input5.text() == "":
            self.display_msg('Error: No length chosen', 'You must select the legth for the hidden data!', 'err')
        else:
            key3 = self.password_input4.text()
            len_data = int(self.password_input5.text())
            
            output_path = self.save_file_photo()
            if output_path == "":
                self.display_msg('Operation cancelled', 'Operation cancelled by user!')
            else:
                try:
                    video_steg.decode(video_file_path, key3, len_data, output_path)
                except video_steg.FileError as fe:
                    self.display_msg('File Error', str(fe), 'err')
                except video_steg.DataError as de:
                    self.display_msg('Data Error', str(de), 'err')
                else:
                    self.video_input.clear()
                    self.display_msg('Success', 'Decoded Successfully!\n\n')
            

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
