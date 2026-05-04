"""Содержит пользовательские исключения для программы стеганографии LSB"""

class FileError(Exception):
    pass

class DataError(Exception):
    pass

class PasswordError(Exception):
    pass
