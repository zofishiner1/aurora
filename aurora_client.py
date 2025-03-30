import requests
import zipfile
import os
from tqdm import tqdm
import json
import vosk
import pyaudio
import random
import re
import pyttsx3
from art import tprint
import websockets
import asyncio

# Инициализация логотипа программы
tprint("AURORA", "tarty1")
vosk.SetLogLevel(-1)

# Базовый URL API
BASE_URL = "http://aurorav.sytes.net:808/api"
access_token = None
key = None

# Настройки аудио
CHUNK = 1024
FORMAT = pyaudio.paInt16
CHANNELS = 1
RATE = 48000

# Функция для получения текста и аудио-потока
async def play_audio(websocket):
    p = pyaudio.PyAudio()
    stream = p.open(format=FORMAT,
                    channels=CHANNELS,
                    rate=RATE,
                    output=True)

    while True:
        try:
            message = await websocket.recv()
            if isinstance(message, str):
                if message == "stream ended":
                    print("Стрим завершен. Закрытие соединения...")
                    break  # Выход из цикла для закрытия соединения
                print(f"Получено сообщение: {message}")
            else:
                # Проигрывание аудио
                stream.write(message)
        except websockets.ConnectionClosed:
            print("Соединение разорвано.")
            break

async def send_text_to_server(text, token):
    async with websockets.connect("ws://aurorav.sytes.net:808/synthesize-and-stream") as websocket:
        # Отправка токена и текста в одном сообщении
        await websocket.send(f"{token}:{text}")
        await play_audio(websocket)

async def main():
    text = "Здравствуйте! Меня зовут Аврора, я виртуальный помощник."
    token = "your_token_here"
    await send_text_to_server(text, token)

def contains_russian_or_special(input_string):
    """Проверка наличия русских букв и специальных символов в строке."""
    pattern = r'[а-яА-Я]|[!@#$%^&*(),.?":{}|<>]'
    return bool(re.search(pattern, input_string))

def encrypt(text, key_string):
    """Шифрование текста с использованием сдвига и XOR."""
    shift_str, xor_key_str = key_string.split(':|:')
    shift = int(shift_str)
    xor_key = int(xor_key_str)
    
    shifted_text = ''.join(chr(ord(char) + shift) for char in text)
    encrypted_text = ''.join(chr(ord(char) ^ xor_key) for char in shifted_text)
    
    return encrypted_text

def decrypt(encrypted_text, key_string):
    """Дешифрование текста с использованием сдвига и XOR."""
    shift_str, xor_key_str = key_string.split(':|:')
    shift = int(shift_str)
    xor_key = int(xor_key_str)
    
    shifted_back_text = ''.join(chr(ord(char) ^ xor_key) for char in encrypted_text)
    decrypted_text = ''.join(chr(ord(char) - shift) for char in shifted_back_text)
    
    return decrypted_text

def register(username, password, key):
    """Регистрация нового пользователя."""
    url = f"{BASE_URL}/register"
    data = {
        "username": username,
        "password": password,
        "key": key
    }
    
    response = requests.post(url, json=data)
    
    if response.status_code == 200:
        return response.json()
    else:
        print("Ошибка регистрации:", response.text)
        return None

def login(username, password):
    """Вход пользователя в систему."""
    url = f"{BASE_URL}/token"
    data = {
        "username": username,
        "password": password
    }
    
    response = requests.post(url, data=data)
    
    if response.status_code == 200:
        return response.json()
    else:
        print("Ошибка входа:", response.text)
        return None

def chat(message, access_token):
    """Отправка сообщения в чат и получение ответа."""
    url = f"{BASE_URL}/chat"
    
    message = encrypt(message, key)
    
    headers = {
        "Authorization": f"Bearer {access_token}",
    }
    
    data = {
        "message": message
    }
    
    print("Аврора: Придумываю ответ...", end='\r')
    
    response = requests.post(url, json=data, headers=headers)
    
    response.encoding = 'utf-8'
    
    if response.status_code == 200:
        return response.json()
    else:
        print("Ошибка в чате:", response.text)
        return None

def search(query, token):
    """Поиск по запросу."""
    url = f"{BASE_URL}/meta_search"
    
    query = encrypt(query, key)
    
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    params = {
        "query": query
    }
    
    response = requests.post(url, headers=headers, params=params)
    
    if response.status_code == 200:
        return response.json()
    else:
        print("Ошибка поиска: ", response.text)

def download_file(filename: str, token: str):
   """Скачивание файла по имени."""
   url = f"{BASE_URL}/file/download"
   params = {
        "filename": filename,
        "token": token
   }
   
   response = requests.get(url, params=params, stream=True)
   if response.status_code == 200:
        total_size = int(response.headers.get('content-length', 0))
        with open(filename, 'wb') as f, tqdm(
            desc=filename,
            total=total_size,
            unit='B',
            unit_scale=True,
            unit_divisor=1024,
        ) as bar:
            for chunk in response.iter_content(chunk_size=1024):
                f.write(chunk)
                bar.update(len(chunk))
        print(f"Файл '{filename}' успешно загружен.")
        
        if filename.endswith('.zip'):
            extract_zip(filename)

def extract_zip(zip_filename: str):
    """Распаковка zip-файла."""
    with zipfile.ZipFile(zip_filename, 'r') as zip_ref:
        file_list = zip_ref.namelist()
        
        with tqdm(total=len(file_list), desc="Распаковка файлов", unit="файл") as pbar:
            for file in file_list:
                zip_ref.extract(file, os.path.dirname(zip_filename))
                pbar.update(1)

    print(f"Файл '{zip_filename}' успешно распакован.")
    os.remove(zip_filename)
    print(f"Файл '{zip_filename}' был удален.")

def list_microphones():
    """Получение списка доступных микрофонов."""
    p = pyaudio.PyAudio()
    mic_list = []
    
    for i in range(p.get_device_count()):
        device_info = p.get_device_info_by_index(i)
        if device_info['maxInputChannels'] > 0:
            mic_list.append((i, device_info['name']))
            
    p.terminate()
    return mic_list

def save_microphone_settings(index):
    """Сохранение настроек микрофона в JSON-файл."""
    with open("mic_settings.json", "w") as f:
        json.dump({"microphone_index": index}, f)

def load_microphone_settings():
    """Загрузка настроек микрофона из JSON-файла."""
    if os.path.exists("mic_settings.json"):
        with open("mic_settings.json", "r") as f:
            return json.load(f)
    return None

def setup_audio_stream(p, input_device_index, channels=1, rate=16000):
    """Настройка аудиопотока для записи звука."""
    return p.open(format=pyaudio.paInt16,
                     channels=channels,
                     rate=rate,
                     input=True,
                     frames_per_buffer=8000,
                     input_device_index=input_device_index)

def find_working_microphone():
    """Автоматический поиск и выбор рабочего микрофона."""
    p = pyaudio.PyAudio()
    microphones = list_microphones()

    for index, name in microphones:
        try:
            stream = setup_audio_stream(p, index)
            stream.close()
            p.terminate()
            print(f"Микрофон с индексом {index} ({name}) работает.")
            save_microphone_settings(index)
            return index
        except OSError as e:
            print(f"Микрофон с индексом {index} ({name}) не работает: {e}")
            continue

    p.terminate()
    print("Не удалось найти рабочий микрофон.")
    return None

def recognize_speech(recognizer, input_device_index):
    """Распознавание речи через микрофон."""
    p = pyaudio.PyAudio()
    
    try:
        stream = setup_audio_stream(p, input_device_index)
    except OSError as e:
        print(f"Произошла ошибка при открытии микрофона: {e}")
        return None

    print("Скажите что-нибудь...")
    
    try:
        while True:
            data = stream.read(8000)
            if (recognizer.AcceptWaveform(data)) and (len(data) > 0):
                result = json.loads(recognizer.Result())
                return result['text']  # Можно добавить таймаут или другие условия выхода из цикла
            
    except Exception as e:
        print(f"Произошла ошибка: {e}")
        return None
    
    finally:
        stream.stop_stream()
        stream.close()
        p.terminate()

async def main():
    while True:
        try:
            user_speech = recognize_speech(recognizer, selected_index)

            if user_speech is not None:
                print("Вы:", user_speech)

                if user_speech.lower().startswith("поиск "):
                    search_query = user_speech[7:].strip()
                    search_response = search(search_query, access_token)
                    search_result = decrypt(search_response['result'], key)
                    print("Результаты поиска:", search_result)

                    # synthesize_speech(search_result, volume=0.9, voice_id=0) # Заменено на connect_and_stream
                    await send_text_to_server(text=search_result, token=access_token)
                    continue

                if contains_russian_or_special(user_speech):
                    chat_response = chat(user_speech, access_token)

                    if chat_response is not None:
                        chat_response_decrypted = decrypt(chat_response['response'], key)
                        print("Ответ от чата:", chat_response_decrypted + "\n\n")
                        # synthesize_speech(chat_response_decrypted, volume=0.9, voice_id=0) # Заменено на connect_and_stream
                        await send_text_to_server(text=chat_response_decrypted, token=access_token)
                else:
                    print("Речь не распознана.") 
        except KeyboardInterrupt:
            print("\nЗавершение работы...")
            break

# Основной код программы
action = int(input("Выберите действие:\n1)Регистрация\n2)Вход в систему\n>> "))
username = input("Имя пользователя>> ")
password = input("Пароль>> ")

if action == 1:
    password_repeat = input("Повторите пароль>> ")
    
    if password == password_repeat:
        key = f"{random.randint(1, 99999)}:|:{random.randint(101, 99999)}"
        user_data = register(username, username, key)

        # Автоматический выбор микрофона
        selected_index = find_working_microphone()

        if selected_index is None:
            print("Не удалось найти рабочий микрофон. Программа завершена.")
            exit()

        if user_data:
            print("Успешно!")
elif action == 2:
    login_data = login(username, username)

    if login_data:
        access_token = login_data['access_token']
        key = login_data['encryption_key']
        
        access_token = decrypt(access_token, key)
        
        print("Успешно!")
        
        try:
            model_path = "vosk-model-small-ru-0.22"
            model_file_path_zip = model_path + ".zip"
            
            model_exists = os.path.exists(model_path)

            if not model_exists:
                print(f"Модель не найдена. Начинается загрузка модели {model_file_path_zip}, ожидайте...")
                download_file(model_file_path_zip, access_token)

            model = vosk.Model(model_path)
            recognizer = vosk.KaldiRecognizer(model, 16000)

            # Загрузка настроек микрофона (если необходимо)
            mic_settings = load_microphone_settings()

            if mic_settings and "microphone_index" in mic_settings:
                selected_index = mic_settings["microphone_index"]
            else:
                print("Настройки микрофона не найдены. Поиск рабочего микрофона...")
                selected_index = find_working_microphone()

                if selected_index is None:
                    print("Не удалось найти рабочий микрофон. Программа завершена.")
                    exit()

            asyncio.run(main())
        except KeyboardInterrupt:
            print("\nЗавершение работы...")
