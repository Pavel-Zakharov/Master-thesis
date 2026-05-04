import os
import shutil
import cv2
import moviepy.video.io.ImageSequenceClip
from moviepy.editor import VideoFileClip, AudioFileClip
from PIL import Image, ImageFile
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import pywt
import wave
from scipy.fftpack import dct, idct


workingDir = 'frames'
frame_count = 0
width = 0
height = 0
output_audio_path = 'frames/reconstructed.wav'


###############################################################################
# AES шифрование/дешифрование и бинарные преобразования
def aes_encrypt(plaintext, password):
    key = get_random_bytes(16)  # Generate a random 128-bit key
    cipher = AES.new(password.encode(), AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return key.hex() + ciphertext.hex()


import time
def aes_decrypt(ciphertext, password):
    # key = bytes.fromhex(ciphertext[:32])  # Extract the key from the ciphertext
    error = 0
    try:
        ciphertext = bytes.fromhex(ciphertext[32:])
    except ValueError:
        time.sleep(30)
        error = 1
        return 0, error
    cipher = AES.new(password.encode(), AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode(), error


def text_to_binary(text):
    binary_array = []
    for char in text:
        binary = bin(ord(char))[2:].zfill(8)
        binary_array.extend([int(bit) for bit in binary])
    return binary_array


def binary_to_text(binary_array):
    text = ""
    for i in range(0, len(binary_array), 8):
        binary = binary_array[i:i+8]
        binary_str = ''.join(str(bit) for bit in binary)
        decimal = int(binary_str, 2)
        text += chr(decimal)
    return text


###############################################################################
### функция RGB в YUV
def rgb2yuv(image_name):
    # загрузка RGB изображения
    frame_path = os.path.join(workingDir, 'framesRGB', image_name)
    rgb_image = cv2.imread(frame_path)
    yuv_image = cv2.cvtColor(rgb_image, cv2.COLOR_RGB2YCrCb)

    # разделение YUV каналов
    Y = yuv_image[:, :, 0]
    U = yuv_image[:, :, 1]
    V = yuv_image[:, :, 2]

    # сохранение каждого канала как отдельное изображение
    frame_path = os.path.join(workingDir, 'framesY', image_name)
    cv2.imwrite(frame_path, Y)
    frame_path = os.path.join(workingDir, 'framesU', image_name)
    cv2.imwrite(frame_path, U)
    frame_path = os.path.join(workingDir, 'framesV', image_name)
    cv2.imwrite(frame_path, V)


### функция YUV в RGB
def yuv2rgb(image_name):
    # Load the 3 separate images
    frame_path = os.path.join(workingDir, 'framesY', image_name)
    Y = cv2.imread(frame_path, 0)
    frame_path = os.path.join(workingDir, 'framesU', image_name)
    U = cv2.imread(frame_path, 0)
    frame_path = os.path.join(workingDir, 'framesV', image_name)
    V = cv2.imread(frame_path, 0)

    yuv_image = np.stack((Y, U, V), axis=-1)

    # конвертация YUV изображения в RGB
    rgb_image = cv2.cvtColor(yuv_image, cv2.COLOR_YCrCb2RGB)

    # сохранение инвертированного RGB изображения в папку
    frame_path = os.path.join(workingDir, 'framesYUV2RGB', image_name)
    cv2.imwrite(frame_path, rgb_image)
    
    
###############################################################################
### функция перемешивания пикселей изображения
def shuffleImage(image, seed):
    # конвертация изображения в массив numpy
    pix = np.array(image)

    # генерация массива перемешанных индексов и начального значения случайного числа для обеспечения одинакового результата
    np.random.seed(seed)
    indices = np.random.permutation(len(pix))

    # перетасовка пикселей, используя индексы
    shuffled = pix[indices].astype(np.uint8)

    # изменение формы перемешанного массива, вернув ему исходные размеры изображения
    shuffled_image = shuffled.reshape(image.shape)

    return shuffled_image


### функция восстановления пикселей изображения
def unshuffleImage(image, seed):
    # получение перемешанных пикселей в массиве numpy
    shuffled = np.array(image)
    nPix = len(shuffled)

    # генерация восстановления
    np.random.seed(seed)
    indices = np.random.permutation(nPix)
    unshuffler = np.zeros(nPix, np.uint32)
    unshuffler[indices] = np.arange(nPix)

    # расстановка пикселей через восстанавливающий массив
    unshuffledPix = shuffled[unshuffler].astype(np.uint8)

    # изменение формы восстановленных пикселей до исходных размеров изображения
    shuffled_image = unshuffledPix.reshape(image.shape)

    return shuffled_image


###############################################################################
### создание директорий, разбиение на кадры, преобразование в YUV и перемешивание пикселей
def process_video(video_file_path, key1):
    # Общая директория для всех кадров
    global workingDir
    
    # удаляем файл, если он уже существует, чтобы избежать конфликтов
    if os.path.exists(workingDir):
        shutil.rmtree(workingDir)
        
    # Создание главной директории
    os.makedirs(workingDir)
    # создание директории для кадров видео
    os.makedirs(os.path.join(workingDir, 'framesRGB'))
    # создание директории для Y U V кадров
    os.makedirs(os.path.join(workingDir, 'framesY'))
    os.makedirs(os.path.join(workingDir, 'framesU'))
    os.makedirs(os.path.join(workingDir, 'framesV'))
    # создание директории для кадров RGB после преобразования из YUV
    os.makedirs(os.path.join(workingDir, 'framesYUV2RGB'))
    
    # чтение файла видео и преобразование его в кадры
    video = cv2.VideoCapture(video_file_path)
    global frame_count
    
    # чтение и сохранение каждого кадра из видео
    while True:
        # чтение следующего кадра
        ret, frame = video.read()
    
        # проверка был ли получен кадр
        if not ret:
            break
    
        # сохранение кадра как файла с изображением
        name_frame = f'{frame_count}.png'
        frame_path = os.path.join(workingDir, 'framesRGB', name_frame)
        cv2.imwrite(frame_path, frame)
    
        # увеличение количества кадров
        frame_count += 1
        
    
    # обработка видео файла
    video.release()
    print(f"Total frames extracted: {frame_count}")
    
    # берем каждый кадр и преобразуем его в 3 отдельных изображения Y U V.
    for i in range(frame_count):
        # даем название файлу отдельного кадра (1.png)
        image_name = str(i) + '.png'
        rgb2yuv(image_name)
    
    
    # перемешиваем пиксели внутри кадров Y U V используя key1
    for i in range(frame_count):
        img_name = str(i) + '.png'
        image_pathY = os.path.join(workingDir, 'framesY', img_name)
        image_pathU = os.path.join(workingDir, 'framesU', img_name)
        image_pathV = os.path.join(workingDir, 'framesV', img_name)
    
        img_y = cv2.imread(image_pathY)
        img_u = cv2.imread(image_pathU)
        img_v = cv2.imread(image_pathV)
    
        result_y = shuffleImage(img_y, key1)
        cv2.imwrite(image_pathY, result_y)
        result_u = shuffleImage(img_u, key1)
        cv2.imwrite(image_pathU, result_u)
        result_v = shuffleImage(img_v, key1)
        cv2.imwrite(image_pathV, result_v)



### берем изображение, преобразуем его в двоичный код и делаем из него массив.
def process_image(photo_file_path, key2):
    global width
    global height
    
    #####
    img = cv2.imread(photo_file_path, 2)
    height, width = img.shape
    ret, bw_img = cv2.threshold(img, 127, 255, cv2.THRESH_BINARY)
    cv2.imwrite("photo_aux.png", bw_img)
    #####
    
    # перетасуем изображение и получим новое (используя key2).
    img = cv2.imread(photo_file_path)
    result = shuffleImage(img, key2)
    cv2.imwrite("hiddenShuffled.png", result)
    
    # читаем файл изображения и преобразуем его в двоичный формат.
    img = cv2.imread('hiddenShuffled.png', 2)
    height, width = img.shape
    ret, bw_img = cv2.threshold(img, 127, 255, cv2.THRESH_BINARY)
    cv2.imwrite("hiddenShuffled.png", bw_img)
    
    # преобразуем изображение в массив numpy
    image_test = np.array(Image.open('hiddenShuffled.png'))
    # присваем переменной этот массив
    x = np.array(image_test)
    # конвертируем в одномерный массив
    y = np.concatenate(x)
    return y


### получаем код Хэмминга из одномерного массива (каждые 4 фрагмента преобразуются в одну последовательность кода)
def hamming_process(key1, key2, y):
    # матрица-генератор G необходимая для кодирования
    G = [
        [1, 1, 0, 1, 0, 0, 0],
        [0, 1, 1, 0, 1, 0, 0],
        [1, 1, 1, 0, 0, 1, 0],
        [1, 0, 1, 0, 0, 0, 1]
    ]
    
    # чтобы получить размеры одного кадра
    global workingDir
    frame_path = os.path.join(workingDir, 'framesY', '0.png')
    Y = cv2.imread(frame_path)
    height, width, channels = Y.shape  # we need width
    dimension = height * width - 1
    
    # чтобы узнать, сколько пикселей нужно изменить в каждом кадре
    # в последнем кадре может быть на несколько пикселей больше
    global frame_count
    nr_pixel = 0  # подсчитать количество измененных пикселей в каждом кадре
    nr_frame = 0  # когда достигаем последнего кадра, то добавляем оставшиеся пиксели, также для перемещения кадров
    pixels_in_frame = (len(y) // 4) // frame_count
    pixels_for_last_frame = (len(y) // 4) % frame_count
    control = 0 # когда доходим до последнего кадра и нужно добавить пиксели
    
    # (Key1 ^ Key2) % 2 == 0 -> начало и конец, в противном случае - наоборот
    parity = 0 # 1 -> начало; -1 -> конец
    if (key1 ^ key2) % 2 == 0:
        parity = 1
    else:
        parity = -1
    
    
    # открытие первых кадры Y U V
    name = '0.png'
    path_y = os.path.join(workingDir, 'framesY', name)
    Y = cv2.imread(path_y)
    path_u = os.path.join(workingDir, 'framesU', name)
    U = cv2.imread(path_u)
    path_v = os.path.join(workingDir, 'framesV', name)
    V = cv2.imread(path_v)
    
    
    # из одномерного массива берем группу из 4 бит для преобразования в код Хэмминга
    for i in range(0, len(y), 4):
        if i + 4 > len(y):
          break
    
        # получаем 4 бита
        aux = y[i:i+4]
        # Умножение двух матриц (1 матрица с 1 строкой и 7 столбцами -> 7 бит)
        aux = np.matmul(aux, G)
        
        # Код Хэмминга во вспомогательном канале (aux)
        for j in range(7):
            # работа в поле %2
            aux[j] %= 2
    
    
        # 3 бита в Y, 2 бита U (первые 2 -> R, G), 2 бита в V (первые 2 -> R, G) -> (используем LSB)
        if nr_pixel == pixels_in_frame:
            nr_pixel = 0
            nr_frame += 1
    
            # закрываем предыдущие YUV кадры
            name = str(nr_frame - 1) + '.png'
            path_y = os.path.join(workingDir, 'framesY', name)
            cv2.imwrite(path_y, Y)
            path_u = os.path.join(workingDir, 'framesU', name)
            cv2.imwrite(path_u, U)
            path_v = os.path.join(workingDir, 'framesV', name)
            cv2.imwrite(path_v, V)
            
            # открываем новые Y U V кадры
            if nr_frame != frame_count:
                name = str(nr_frame) + '.png'
                path_y = os.path.join(workingDir, 'framesY', name)
                Y = cv2.imread(path_y)
                path_u = os.path.join(workingDir, 'framesU', name)
                U = cv2.imread(path_u)
                path_v = os.path.join(workingDir, 'framesV', name)
                V = cv2.imread(path_v)
            else:
                break
    
    
        # если это последний кадр, то у нас больше пикселей (при делении на остаток)
        if control == 0 and nr_frame == frame_count - 1:
            pixels_in_frame += pixels_for_last_frame
            control = 1
    
        # LSB становится кодом Хэмминга (хранится во aux)
        if parity == 1:
            Y[nr_pixel // width][nr_pixel % width][0] = (Y[nr_pixel // width][nr_pixel % width][0] & ~1) | aux[0]
            Y[nr_pixel // width][nr_pixel % width][1] = (Y[nr_pixel // width][nr_pixel % width][1] & ~1) | aux[1]
            Y[nr_pixel // width][nr_pixel % width][2] = (Y[nr_pixel // width][nr_pixel % width][2] & ~1) | aux[2]
    
            U[nr_pixel // width][nr_pixel % width][0] = (U[nr_pixel // width][nr_pixel % width][0] & ~1) | aux[3]
            U[nr_pixel // width][nr_pixel % width][1] = (U[nr_pixel // width][nr_pixel % width][1] & ~1) | aux[4]
    
            V[nr_pixel // width][nr_pixel % width][0] = (V[nr_pixel // width][nr_pixel % width][0] & ~1) | aux[5]
            V[nr_pixel // width][nr_pixel % width][1] = (V[nr_pixel // width][nr_pixel % width][1] & ~1) | aux[6]
    
            parity = -1
        else:
            contor = dimension - nr_pixel
            Y[contor // width][contor % width][0] = (Y[contor // width][contor % width][0] & ~1) | aux[0]
            Y[contor // width][contor % width][1] = (Y[contor // width][contor % width][1] & ~1) | aux[1]
            Y[contor // width][contor % width][2] = (Y[contor // width][contor % width][2] & ~1) | aux[2]
    
            U[contor // width][contor % width][0] = (U[contor // width][contor % width][0] & ~1) | aux[3]
            U[contor // width][contor % width][1] = (U[contor // width][contor % width][1] & ~1) | aux[4]
    
            V[contor // width][contor % width][0] = (V[contor // width][contor % width][0] & ~1) | aux[5]
            V[contor // width][contor % width][1] = (V[contor // width][contor % width][1] & ~1) | aux[6]
    
            parity = 1
    
        nr_pixel += 1
    
    
    name = str(frame_count - 1) + '.png'
    path_y = os.path.join(workingDir, 'framesY', name)
    cv2.imwrite(path_y, Y)
    path_u = os.path.join(workingDir, 'framesU', name)
    cv2.imwrite(path_u, U)
    path_v = os.path.join(workingDir, 'framesV', name)
    cv2.imwrite(path_v, V)


### берем встроенные кадры, перемешиваем их, преобразуем из YUV в RGB, затем возвращаем к видеоформату .avi
def transform_back_to_video(key1):
    global workingDir
    global frame_count
    
    # восстановление
    for i in range(frame_count):
        img_name = str(i) + '.png'
        image_pathY = os.path.join(workingDir, 'framesY', img_name)
        image_pathU = os.path.join(workingDir, 'framesU', img_name)
        image_pathV = os.path.join(workingDir, 'framesV', img_name)
    
        img_y = cv2.imread(image_pathY)
        img_u = cv2.imread(image_pathU)
        img_v = cv2.imread(image_pathV)
    
        result_y = unshuffleImage(img_y, key1)
        cv2.imwrite(image_pathY, result_y)
        result_u = unshuffleImage(img_u, key1)
        cv2.imwrite(image_pathU, result_u)
        result_v = unshuffleImage(img_v, key1)
        cv2.imwrite(image_pathV, result_v)
        
    
    # обратная ситуация (из YUV файлов преобразуем обратно в RGB кадры) -> папка framesYUV2RGB
    for i in range(frame_count):
        image_name = str(i) + '.png'
        yuv2rgb(image_name)
    
    # перевод в видео формат
    ImageFile.LOAD_TRUNCATED_IMAGES = True
    image_files = []

    for img_number in range(frame_count): 
        image_files.append('frames/framesYUV2RGB/' + str(img_number) + '.png') 
    
    fps = 30
    
    clip = moviepy.video.io.ImageSequenceClip.ImageSequenceClip(image_files, fps=fps)
    clip.write_videofile("intermediar.avi", codec='libx264')
   
    
    
############################################################################### 
### шифрование/дешифрование аудио
def encode_audio(data, message, delta = 5):
    segments = np.array_split(data, len(message))
    segments = segments.copy()
    rsegments = []

    for ind, segment in enumerate(segments):

        cA1, cD1 = pywt.dwt(segment, 'db1')

        v = dct(cA1, norm='ortho')

        v1 = v[::2]
        v2 = v[1::2]

        nrmv1 = np.linalg.norm(v1, ord=2)
        nrmv2 = np.linalg.norm(v2, ord=2)

        u1 = v1 / nrmv1
        u2 = v2 / nrmv2

        watermark_bit = message[ind]
        nrm = (nrmv1 + nrmv2) / 2
        if watermark_bit == 1:
            nrmv1 = nrm + delta
            nrmv2 = nrm - delta
        else:
            nrmv1 = nrm - delta
            nrmv2 = nrm + delta

        rv1 = nrmv1 * u1
        rv2 = nrmv2 * u2

        rv = np.zeros((len(v),))

        rv[::2] = rv1
        rv[1::2] = rv2

        rcA1 = idct(rv, norm='ortho')

        rseg = pywt.idwt(rcA1, cD1, 'db1')
        rsegments.append(rseg[:])

    return np.concatenate(rsegments)


def decode_audio(data_with_watermark, watermark_length, delta = 5):
    segments = np.array_split(data_with_watermark, watermark_length)
    segments = segments.copy()
    watermark_bits = []

    for ind, segment in enumerate(segments):
        cA1, cD1 = pywt.dwt(segment, 'db1')

        v = dct(cA1, norm='ortho')

        v1 = v[::2]
        v2 = v[1::2]

        nrmv1 = np.linalg.norm(v1, ord=2)
        nrmv2 = np.linalg.norm(v2, ord=2)

        if nrmv1 > nrmv2:
            watermark_bits.append(1)
        else:
            watermark_bits.append(0)

    return watermark_bits


### восстановление аудио из массива
def reconstruct_audio(signal, parameters):
    '''
    Параметры:
      signal - одномерный массив numpy, представляющий сигнал с водяным знаком
      parameters - кортеж параметров аудио, полученных из audio.getparams()
    Возвращает:
      Восстановленный аудиосигнал - одномерный массив numpy
    '''

    # frames = len(signal)
    sample_width = parameters.sampwidth
    audio_frames = signal.astype(np.uint8 if sample_width == 1 else np.int16).tobytes()

    audio = wave.open("reconstructed.wav", 'wb')
    audio.setparams(parameters)
    audio.writeframes(audio_frames)
    audio.close()
    
    
###############################################################################
### обработка звука
def process_audio(video_file_path, key1, key2, key3, y):
    global width
    global height
    
    # получение оригинального звукв из оригинального видео
    source_video = VideoFileClip(video_file_path)
    source_video.audio.write_audiofile(r"audio_original.wav") 
    
    audio = wave.open("audio_original.wav", 'r')
    parameters = audio.getparams()  # будет использоваться для восстановления стегоаудио
    frames = audio.getnframes() # количество кадров аудио
    sample_width = audio.getsampwidth() # ширина выборки в байтах
    audio_frames = audio.readframes(frames)
    rawdata = np.frombuffer(audio_frames, dtype=np.uint8 if sample_width == 1 else np.int16)
    rawData = np.copy(rawdata)
    
    # создание секретного сообщения
    message = f'Key1 = {key1}; Key2 = {key2}; Width X Height = {width} X {height}; Len(y) = {y}'
    print(message)
    encrypted_msg = aes_encrypt(message, key3)
    binary_msg = text_to_binary(encrypted_msg)
    print("Length Hidden Data: ", len(binary_msg))
    
    # шифрование и создание нового стего аудио
    aux = encode_audio(rawData, binary_msg)
    reconstruct_audio(aux, parameters)
    
    
### прикрепление стего-аудио к стего-видео (создание итогового видео)
def attach_stego_audio(output_path):
   audio_clip = AudioFileClip(r"reconstructed.wav")
   destination_video = VideoFileClip("intermediar.avi")
   final_clip = destination_video.set_audio(audio_clip)
   # сохранение последнего фрагмента
   final_clip.write_videofile(output_path, codec='libx264')     
    
    

###############################################################################    
### Основная функция кодирования (стего-видео)
def encode(video_file_path, photo_file_path, key1, key2, key3, output_path):
    process_video(video_file_path, key1)
    y = process_image(photo_file_path, key2) # len_img
    hamming_process(key1, key2, y)
    transform_back_to_video(key1)
    process_audio(video_file_path, key1, key2, key3, len(y))
    attach_stego_audio(output_path)
    
    
###############################################################################
### Функция, принимающая стего-аудио и извлекающая скрытые данные
def process_stego_audio(video_file_path, key3, len_data, output_path):
    global output_audio_path
    video_clip = VideoFileClip(video_file_path)
    video_clip.audio.write_audiofile(output_audio_path)
    audio = wave.open("reconstructed.wav", 'r')
    frames = audio.getnframes() # количество кадров аудио
    sample_width = audio.getsampwidth() # ширина выборки в байтах
    audio_frames = audio.readframes(frames)
    rawdata = np.frombuffer(audio_frames, dtype=np.uint8 if sample_width == 1 else np.int16)
    rawData = np.copy(rawdata)
    result = decode_audio(rawData, len_data)
    newString = binary_to_text(result)
    decrypted_msg, error = aes_decrypt(newString, key3)
    if error:
        img = cv2.imread("photo_aux.png")
        copied_img = img.copy()
        cv2.imwrite(output_path, copied_img)
        return -1, -1, -1, -1, -1
    os.remove(output_audio_path)
    pairs = decrypted_msg.split(";")
    key1 = None
    key2 = None
    width = None
    height = None
    len_y = None
    for pair in pairs:
        pair = pair.strip()
        key, value = pair.split("=")
        key = key.strip()
        value = value.strip()
        if key == "Key1":
            key1 = int(value)
        elif key == "Key2":
            key2 = int(value)
        elif key == "Width X Height":
            width, height = map(int, value.split("X"))
        elif key == "Len(y)":
            len_y = int(value)
    return key1, key2, width, height, len_y


### Извлечение скрытого изображения из стего-видео
def extract_hidden_photo(video_file_path, key1, key2, width_photo, height_photo, len_y, output_path):
    global workingDir
    global frame_count
    
    video = cv2.VideoCapture(video_file_path)
    # проверка успешно ли открыт видеофайл
    if not video.isOpened():
        print("Error opening video file")
        exit()
    
    frame_count = 0
    # читаем и сохраняем каждый кадр из видео
    while True:
        # чтение следующего кадра
        ret, frame = video.read()
    
        # проверка был ли получен кадр
        if not ret:
            break
    
        # сохранение кадра как изображение
        name_frame = f'{frame_count}.png'
        frame_path = os.path.join(workingDir, 'framesRGB', name_frame)
        cv2.imwrite(frame_path, frame)
    
        # подсчет количества кадров
        frame_count += 1
    
    #  обработка видео файла
    video.release()
    print(f"Total frames extracted: {frame_count}")
    
    # перетасовка
    for i in range(frame_count):
        img_name = str(i) + '.png'
        image_pathY = os.path.join(workingDir, 'framesY', img_name)
        image_pathU = os.path.join(workingDir, 'framesU', img_name)
        image_pathV = os.path.join(workingDir, 'framesV', img_name)
    
        img_y = cv2.imread(image_pathY)
        img_u = cv2.imread(image_pathU)
        img_v = cv2.imread(image_pathV)
    
        result_y = shuffleImage(img_y, key1)
        cv2.imwrite(image_pathY, result_y)
        result_u = shuffleImage(img_u, key1)
        cv2.imwrite(image_pathU, result_u)
        result_v = shuffleImage(img_v, key1)
        cv2.imwrite(image_pathV, result_v)
    
    
    # Матрица четности H - необходима для коррекции ошибок
    H = [
         [1, 0, 0],
         [0, 1, 0],
         [0, 0, 1],
         [1, 1, 0],
         [0, 1, 1],
         [1, 1, 1],
         [1, 0, 1]
    ]
    message_retrieved = np.zeros(len_y, dtype = np.uint8)
    message_len = 0  ### Таким образом, мы перемещаем пиксели одномерного массива сверху
    
    # чтобы получить размер одного кадра
    frame_path = os.path.join(workingDir, 'framesY', '0.png')
    Y = cv2.imread(frame_path)
    height, width, channels = Y.shape  ### нам нужна ширина
    dimension = height * width - 1
    
    # Чтобы узнать сколько пикселей нам нужно прочитать в каждом кадре
    # В последнем кадре может быть на несколько пикселей больше
    pixels_in_frame = (len_y // 4) // frame_count
    pixels_for_last_frame = (len_y // 4) % frame_count
    
    # (Key1 ^ Key2) % 2 == 0 -> начало и конец, в противном случае - наоборот 
    parity = 0 # 1 -> начало; -1 -> конец
    if (key1 ^ key2) % 2 == 0:
        parity = 1
    else:
        parity = -1
    
    # Aux будет содержать код Хэмминга извлеченный из кадра
    aux = [0, 0, 0, 0, 0, 0, 0] 
    # Из каждого кадра извлекаем измененные пиксели
    for i in range(frame_count):
        # Если это последний кадр, то у нас может быть больше пикселей
        if i == frame_count - 1:
            pixels_in_frame += pixels_for_last_frame
        
        # Открываем кадры, из которых мы будем считывать пиксели
        name = str(i) + '.png'
        path_y = os.path.join(workingDir, 'framesY', name)
        Y = cv2.imread(path_y)
        path_u = os.path.join(workingDir, 'framesU', name)
        U = cv2.imread(path_u)
        path_v = os.path.join(workingDir, 'framesV', name)
        V = cv2.imread(path_v)
        
        ### читаем измененные пиксели
        for j in range(pixels_in_frame):
            if parity == 1:
                aux[0] = Y[j // width][j % width][0] % 2
                aux[1] = Y[j // width][j % width][1] % 2
                aux[2] = Y[j // width][j % width][2] % 2
    
                aux[3] = U[j // width][j % width][0] % 2
                aux[4] = U[j // width][j % width][1] % 2
    
                aux[5] = V[j // width][j % width][0] % 2
                aux[6] = V[j // width][j % width][1] % 2
    
                parity = -1
            else:
                contor = dimension - j
                aux[0] = Y[contor // width][contor % width][0] % 2
                aux[1] = Y[contor // width][contor % width][1] % 2
                aux[2] = Y[contor // width][contor % width][2] % 2
    
                aux[3] = U[contor // width][contor % width][0] % 2
                aux[4] = U[contor // width][contor % width][1] % 2
    
                aux[5] = V[contor // width][contor % width][0] % 2
                aux[6] = V[contor // width][contor % width][1] % 2
    
                parity = 1
    
            # коррекция ошибок
            Z = np.matmul(aux, H)
            Z[0] %= 2
            Z[1] %= 2
            Z[2] %= 2
    
            # Ошибок нет (все нули)
            if Z[0] == 0 and Z[1] == 0 and Z[2] == 0:
                message_retrieved[message_len] = aux[3] * 255
                message_len += 1
                message_retrieved[message_len] = aux[4] * 255
                message_len += 1
                message_retrieved[message_len] = aux[5] * 255
                message_len += 1
                message_retrieved[message_len] = aux[6] * 255
                message_len += 1
            elif Z[0] == 1 and Z[1] == 1 and Z[2] == 0:
                message_retrieved[message_len] = ((aux[3] + 1) % 2) * 255
                message_len += 1
                message_retrieved[message_len] = aux[4] * 255
                message_len += 1
                message_retrieved[message_len] = aux[5] * 255
                message_len += 1
                message_retrieved[message_len] = aux[6] * 255
                message_len += 1
            elif Z[0] == 0 and Z[1] == 1 and Z[2] == 1:
                message_retrieved[message_len] = aux[3] * 255
                message_len += 1
                message_retrieved[message_len] = ((aux[4] + 1) % 2) * 255
                message_len += 1
                message_retrieved[message_len] = aux[5] * 255
                message_len += 1
                message_retrieved[message_len] = aux[6] * 255
                message_len += 1
            elif Z[0] == 1 and Z[1] == 1 and Z[2] == 1:
                message_retrieved[message_len] = aux[3] * 255
                message_len += 1
                message_retrieved[message_len] = aux[4] * 255
                message_len += 1
                message_retrieved[message_len] = ((aux[5] + 1) % 2) * 255
                message_len += 1
                message_retrieved[message_len] = aux[6] * 255
                message_len += 1
            elif Z[0] == 1 and Z[1] == 0 and Z[2] == 1:
                message_retrieved[message_len] = aux[3] * 255
                message_len += 1
                message_retrieved[message_len] = aux[4] * 255
                message_len += 1
                message_retrieved[message_len] = aux[5] * 255
                message_len += 1
                message_retrieved[message_len] = ((aux[6] + 1) % 2) * 255
                message_len += 1
        
        # Закрываем предыдущие YUV кадры
        name = str(i) + '.png'
        path_y = os.path.join(workingDir, 'framesY', name)
        cv2.imwrite(path_y, Y)
        path_u = os.path.join(workingDir, 'framesU', name)
        cv2.imwrite(path_u, U)
        path_v = os.path.join(workingDir, 'framesV', name)
        cv2.imwrite(path_v, V)
    
    name = str(i - 1) + '.png'
    path_y = os.path.join(workingDir, 'framesY', name)
    cv2.imwrite(path_y, Y)
    path_u = os.path.join(workingDir, 'framesU', name)
    cv2.imwrite(path_u, U)
    path_v = os.path.join(workingDir, 'framesV', name)
    cv2.imwrite(path_v, V)
    
    # извлекаем спрятанное изображение
    img = message_retrieved.reshape((height_photo, width_photo))
    cv2.imwrite(output_path, img)
    
    img_y = cv2.imread(output_path)
    result_y = unshuffleImage(img_y, key2)
    cv2.imwrite(output_path, result_y)


###############################################################################   
### Основная функция декодирования (стего-видео)
def decode(video_file_path, key3, len_data, output_path):
    key1, key2, width, height, len_y = process_stego_audio(video_file_path, key3, len_data, output_path)
    if key1 == -1:
        return
    else:
        extract_hidden_photo(video_file_path, key1, key2, width, height, len_y, output_path)
      