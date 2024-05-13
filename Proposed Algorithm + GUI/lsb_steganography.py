"""              Предлагаемый алгоритм LSB              """
import os         
import binascii
import pbkdf2
import pyaes
import hashlib
import random
import numpy as np
from PIL import Image
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from custom_exceptions import *

########################################    ШИФРОВАНИЕ + ДЕШИФРОВАНИЕ СООБЩЕНИЯ
# https://cryptobook.nakov.com/symmetric-key-ciphers/aes-encrypt-decrypt-examples
# должны быть одинаковыми для шифрования и дешифрования
passwordSalt = b'\\`\xd6\xdaB\x03\xdd\xd4z\xb6p\xe8O\xf0\xa8\xc0'
iv = 12276418801510358845029257473125458269416880639997527613362129559241916371076
def encrypt(text, passwd):
    """
        Derives a 256-bit key using the PBKDF2 key derivation algorithm from the password. It uses a random 
        password derivation salt (128-bit). This salt should be stored in the output, together with the ciphertext, 
        because without it the decryption key cannot be derived again and the decryption will be impossible.
        The derived key consists of 64 hex digits (32 bytes), which represents a 256-bit integer number.
    """
    key = pbkdf2.PBKDF2(passwd, passwordSalt).read(32)  
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    cipherByte = aes.encrypt(text)
    return binascii.hexlify(cipherByte).decode('utf-8')   # hex digits

def decrypt(text, passwd):
    res = bytes(text, 'utf-8')
    cipherByte = binascii.unhexlify(res)
    key = pbkdf2.PBKDF2(passwd, passwordSalt).read(32)
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    originalByte = aes.decrypt(cipherByte)
    return originalByte.decode('utf-8')


###################################################   ШИФРОВАНИЕ + ДЕШИФРОВАНИЕ ФАЙЛА ПИКСЕЛЕЙ
# https://www.novixys.com/blog/using-aes-encryption-decryption-python-pycrypto/
def encrypt_file(key, in_filename, out_filename=None, chunksize=64 * 1024):
    if not out_filename:
        out_filename = in_filename + '.enc'
    iv = get_random_bytes(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))


def decrypt_file(key, in_filename, out_filename=None, chunksize=24 * 1024):
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]
    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)
        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)


# Функция, преобразующая любой тип данных в двоичный
def textToBinary(text):
    binar = list(format(c, '08b') for c in bytearray(text.encode('latin-1')))
    return binar


def PixelsRandom(width, height, lenEncodedMessage):
    new = []
    Pixels = []
    for i in range(width * height):
        new.append(i)
    for i in range(len(new) - 1, 0, -1):
        j = random.randint(0, i + 1)
        new[i], new[j] = new[j], new[i]
    for i in range(lenEncodedMessage * 3):
        Pixels.append(new[i])
    vectorPixels = np.array(Pixels)
    np.savetxt("pixelsSequence.txt", vectorPixels, delimiter="\t")
    return Pixels


def encodeAux(imgAux, encodedMessage, output_filepath, passwordPixels, progressBar): 
    width, height = imgAux.size
    # создает последовательность смешанных пикселей
    Pixels = PixelsRandom(width, height, len(encodedMessage))
    textB = textToBinary(encodedMessage)  
    dr = 0
    progress = 0
    total_bits = 32 + len(encodedMessage) * 7
    progress_fraction = 1 / total_bits
    for i in range(0, len(encodedMessage) * 3, 3):
        dc = 0
        for j in range(0, 3):
            rr = Pixels[i + j] // height
            rc = Pixels[i + j] % height
            rgb = imgAux.getpixel((rr, rc))
            value = []
            idx = 0
            for k in rgb:
                if (k % 2 == 0 and textB[dr][dc] == '1'):
                    if (k == 0):
                        k += 1
                    else:
                        k -= 1
                if (k % 2 == 1 and textB[dr][dc] == '0'):
                    k -= 1
                value.append(k)
                idx += 1
                dc += 1
                
                if progressBar != None: 
                    progress += progress_fraction
                    progressBar.setValue(progress * 100)
                
                if (dc >= 8):
                    break
            if (dc >= 8):
                value.append(rgb[2])
            newrgb = (value[0], value[1], value[2])
            imgAux.putpixel((rr, rc), newrgb)
        dr += 1
     
    imgAux.save(output_filepath, str(output_filepath.split(".")[1].upper()))
    key = hashlib.sha256(passwordPixels.encode()).digest()
    encrypt_file(key, 'pixelsSequence.txt')
         

# Основная функция для кодирования
def encode(input_filepath, text, output_filepath, passwordPhoto, passwordPixels, progressBar = None): 
    image = Image.open(input_filepath, 'r') 
    encodedMessage = encrypt(text, passwordPhoto)    # кодируем текст с помощью заданного пароля

    imgAux = image.copy() 
    width, height = imgAux.size

    # Проверяем, чтобы размер секретного сообщения не превышал объем изображения
    nr_bytes = width * height * 3 // 8
    if (nr_bytes < len(text)):
      raise ValueError(f"Insufficient bytes: choose a larger image or reduce the size of the message!\nMaximum number of bytes: {nr_bytes}")
    else:
      encodeAux(imgAux, encodedMessage, output_filepath, passwordPixels, progressBar)


# Основная функция декодирования
def decode(input_path, input_path_Pixels, passwordPhoto, passwordPixels, progressBar = None): 
    key = hashlib.sha256(passwordPixels.encode()).digest()
    decrypt_file(key, input_path_Pixels, 'out.txt')
    Pixels = np.genfromtxt('out.txt', delimiter='\t')

    if os.path.exists("out.txt"):
        os.remove("out.txt")
        
    os.remove(input_path_Pixels)

    decodedTextInBits = []
    img = Image.open(input_path, 'r') 
    width, height = img.size
    progress = 0
    for i in range(0, len(Pixels), 3):
        ithChar = ""
        for j in range(0, 3):
            rr = Pixels[i + j] // height
            rc = Pixels[i + j] % height
            rgb = img.getpixel((rr, rc))
            for k in rgb:
                if (k & 1):
                    ithChar += '1'
                else:
                    ithChar += '0'

        ithChar = ithChar[:-1]
        decodedTextInBits.append((ithChar))
        
        if progressBar != None: 
            progress += 1
            progressBar.setValue(progress * 100)
        
    decodedText = ''
    for i in decodedTextInBits:
        decodedText += chr(int(i, 2))
    
    messageSecret = decrypt(decodedText, passwordPhoto)
    return messageSecret


