from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import aiohttp
from bs4 import BeautifulSoup
from pydantic import BaseModel
import hashlib
import json
import asyncio
import os
import logging
import sys
from colorama import Fore, Style
from fastapi.responses import StreamingResponse
import re
import aiosqlite
import string
import random
import ollama

async def upd_ip():
    """
    Обновляет внешний IP-адрес для указанных доменов.
    Запрашивает внешний IP-адрес с помощью API и обновляет его для доменов No-IP.
    Запускается в бесконечном цикле с интервалом в 1 час.
    """
    username = '64wk4be'
    password = '64izznExMUaY'
    hostname = 'aurorav.sytes.net'

    async with aiohttp.ClientSession() as session:
        while True:
            # Получение текущего внешнего IP-адреса
            try:
                async with session.get('https://api.ipify.org', timeout=10) as response:
                    response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
                    current_ip = await response.text()
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                print(f'Ошибка при получении IP: {e}')
                await asyncio.sleep(60)  # Retry after 60 seconds
                continue

            # Формирование URL для обновления IP-адреса на No-IP
            update_url = f'https://{username}:{password}@dynupdate.no-ip.com/nic/update?hostname={hostname}&myip={current_ip}'

            # Отправка запроса на обновление
            try:
                async with session.get(update_url, timeout=10) as update_response:
                    update_response.raise_for_status()
                    update_text = await update_response.text()
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                print(f'Ошибка при обновлении IP: {e}')
                await asyncio.sleep(60)
                continue

            # Проверка результата обновления
            if re.match(r'^(good|nochg)', update_text):
                print(f'IP адрес успешно обновлён: {current_ip}')
            else:
                print('Ошибка при обновлении IP:', update_text)

            # Ожидание 1 час перед следующим обновлением
            await asyncio.sleep(3600)

# Настройка логгирования
class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        log_color = self.COLORS.get(record.levelname, Fore.WHITE)
        message = super().format(record)
        return f"{log_color}{message}{Style.RESET_ALL}"

def setup_logging():
    """
    Настройка логгирования для приложения.
    Создает обработчики для записи логов в файл и вывода на консоль с цветовой разметкой.
    Возвращает настроенный логгер.
    """
    file_handler = logging.FileHandler('data/app.log')
    file_handler.setLevel(logging.INFO)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger = logging.getLogger('my_logger')
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger

logger = logging.getLogger(__name__)

class UserStorage:
    """Класс для хранения и управления пользователями с использованием SQLite."""
    
    def __init__(self, db_name='data/user_data.db'):
        self.db_name = db_name
        self.key = None
        self.connection = None # Initialize connection to None

    async def connect(self):
         self.connection = await aiosqlite.connect(self.db_name)

    async def hash_password(self, password):
        """Хеширует пароль с использованием SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()

    async def create_table(self):
        """Создаёт таблицу для хранения пользователей."""
        async with self.connection.cursor() as cursor:
            await cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL,
                    token TEXT NOT NULL,
                    key TEXT NOT NULL,
                    history TEXT DEFAULT ''
                )
            ''')
            await self.connection.commit()
            logger.info("Таблица 'users' создана или уже существует.")

    async def add_user(self, username, password, key):
        """Добавляет нового пользователя в таблицу."""
        token = hashlib.sha256(username.encode()).hexdigest()
        
        try:
            async with self.connection.cursor() as cursor:
                await cursor.execute('''
                    INSERT INTO users (username, password, token, key) VALUES (?, ?, ?, ?)
                ''', (username, await self.hash_password(password), token, key))
                await self.connection.commit()
            logger.info(f"Пользователь '{username}' добавлен.")
            return token
        except aiosqlite.IntegrityError:
            logger.warning(f"Пользователь '{username}' уже существует.")
            return False

    async def get_user_by_username(self, username):
        """Получает информацию о пользователе по имени пользователя."""
        async with self.connection.cursor() as cursor:
            await cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            return await cursor.fetchone()

    async def get_user_by_token(self, token):
        """Получает информацию о пользователе по токену."""
        async with self.connection.cursor() as cursor:
            await cursor.execute('SELECT * FROM users WHERE token = ?', (token,))
            return await cursor.fetchone()

    async def get_key_by_token(self, token):
        """Получает ключ пользователя по токену."""
        user_info = await self.get_user_by_token(token)
        
        if user_info:
            return user_info[3]  # user_info[3] - это ключ
        return None

    async def verify_user(self, username, password):
        """Проверяет учетные данные пользователя."""
        user_info = await self.get_user_by_username(username)
        
        if user_info and user_info[1] == await self.hash_password(password):  # user_info[1] - это пароль
            return user_info[2]  # user_info[2] - это токен
        return None
    
    async def token_exists(self, token):
        """Проверяет существование токена в базе данных."""
        async with self.connection.cursor() as cursor:
            await cursor.execute('SELECT 1 FROM users WHERE token = ?', (token,))
            result = await cursor.fetchone()
            return result is not None

    async def close(self):
        """Закрывает соединение с базой данных."""
        if self.connection:
            await self.connection.close()

# Проверяем наличие директории filesCLIENT и создаем ее, если не существует
if not os.path.exists('data/filesCLIENT/'):
    os.makedirs('data/filesCLIENT/')

async def download_file(url, filepath):
    """Асинхронная функция для скачивания файла."""
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url) as response:
                response.raise_for_status()
                with open(filepath, 'wb') as f:
                    while True:
                        chunk = await response.content.read(8192)
                        if not chunk:
                            break
                        f.write(chunk)
                print(f"Файл {filepath} успешно загружен.")
                return True
        except aiohttp.ClientError as e:
            print(f"Ошибка при загрузке файла {filepath}: {e}")
            return False

# Проверяем наличие zip-файла модели
async def check_and_download_model():
    if not os.path.isfile('data/filesCLIENT/vosk-model-small-ru-0.22.zip'):
        print("Файл data/filesCLIENT/vosk-model-small-ru-0.22.zip не найден. Начинаю загрузку...")
        url = "https://alphacephei.com/vosk/models/vosk-model-small-ru-0.22.zip"
        await download_file(url, 'data/filesCLIENT/vosk-model-small-ru-0.22.zip')
    else:
        print("Файл data/filesCLIENT/vosk-model-small-ru-0.22.zip уже существует.")

# Проверяем наличие лог-файла и создаем его, если не существует
if not os.path.isfile('data/app.log'):
    open('data/app.log', 'w').close()  # Просто создаем файл без записи
    print("Файл data/app.log успешно создан.")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
logger = setup_logging()
app = FastAPI()
user_storage = UserStorage()

async def meta_search(query):
    """Выполняет метапоиск по заданному запросу, используя несколько поисковых систем.
    
    Аргументы:
        query (str): Запрос для поиска, который будет отправлен в поисковые системы.
    
    Возвращает:
        str: Объединённый текст результатов поиска, очищенный от дубликатов и лишней инфомации.
    """

    async def search_engine(name, url, params):
        """Выполняет HTTP GET запрос к указанному URL с заданными параметрами.
        
        Аргументы:
            url (str): URL поисковой системы для выполнения запроса.
            params (dict): Параметры запроса, включая поисковый запрос.
        
        Возвращает:
            str: Ответ от сервера в виде HTML текста.
        """
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                          "(KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537."
                          "3"
        }
        
        try:
            async with session.get(url=url,
                                   headers=headers,
                                   params=params,
                                   timeout=10) as response:
                response.raise_for_status()
                text = await response.text()
                print(f"Metasearch.{name}")
                return text
        except Exception as e:
            print(f"Metasearch.{name} Error: {e}")
            return ""

    async def extract_text_from_html(html):
        """Извлекает текст из HTML-кода полученного от поисковой системы."""
        
        soup = BeautifulSoup(html or "", 'html.parser')
        
        # Извлекаем все элементы содержимого страницы
        content_elements = soup.find_all(['p', 'h1', 'h2', 'h3'])
        
        extracted_text = '\n'.join([element.get_text() for element in content_elements])
        
        
        return extracted_text

    # Создаем одну общую сессию для всех запросов
    async with aiohttp.ClientSession() as session:

        # Выполнение поиска в различных системах
        google_results = await search_engine("Google", "https://www.google.com/search", {"q": query})
        yahoo_results = await search_engine("Yahoo", "https://search.yahoo.com/search", {"p": query})

    # Объединение результатов из всех систем
    combined_texts = [
        await extract_text_from_html(google_results),
        await extract_text_from_html(yahoo_results)
    ]

    combined_texts_filtered = [text for text in combined_texts if text] # Удаляем пустые строки

    system_prompt="""
    ДАЛЕЕ БУДЕТ ПРЕДОСТАВЛЕН ТЕКСТ УДАЛЯЙТЕ ПОВТОРЯЮЩИЕСЯ ДАННЫЕ ОТВЕТ ДОЛЖЕН БЫТЬ ЯСНЫМ И КОНКРЕТНЫМ ИЗБЕГАЙТЕ ИЗЛИШНЕЙ ИНФОРМАЦИИ СФОРМУЛИРУЙТЕ ОТВЕТ С УЧЁТОМ ТОЛЬКО НОВЫХ ФАКТОВ СОДЕРЖИТ
    """

    result_combined='\n'.join(combined_texts_filtered)

    result_ollama=ollama.generate(
        model='llama3.1',
        system=system_prompt,
        prompt=result_combined)['response']

    return result_ollama

async def encrypt(text, key_string):
    """Шифрует текст с использованием сдвига и XOR шифрования.

    Парсит строку ключа в формате 'xxx:|:xxx' и возвращает зашифрованный текст.

    Аргументы:
        text (str): Текст, который необходимо зашифровать.
        key_string (str): Строка ключа в формате 'shift:|:xor_key', где:
            - shift (int): Значение сдвига для шифрования.
            - xor_key (int): Ключ для операции XOR.

    Возвращает:
        str: Зашифрованный текст.
    """
    # Парсинг строки ключа
    shift_str, xor_key_str = key_string.split(':|:')
    
    # Преобразование строк в целые числа
    shift = int(shift_str)
    xor_key = int(xor_key_str)

    # Сдвиг каждого символа по юникоду
    shifted_text = ''.join(chr(ord(char) + shift) for char in text)
    
    # Применение XOR шифрования
    encrypted_text = ''.join(chr(ord(char) ^ xor_key) for char in shifted_text)
    
    return encrypted_text

async def decrypt(encrypted_text, key_string):
    """Расшифровывает текст с использованием обратного сдвига и XOR шифрования.

    Парсит строку ключа в формате 'xxx:|:xxx' и возвращает расшифрованный текст.

    Аргументы:
        encrypted_text (str): Зашифрованный текст, который необходимо расшифровать.
        key_string (str): Строка ключа в формате 'shift:|:xor_key', где:
            - shift (int): Значение сдвига для расшифровки.
            - xor_key (int): Ключ для операции XOR.

    Возвращает:
        str: Расшифрованный текст.
    """
    # Парсинг строки ключа
    shift_str, xor_key_str = key_string.split(':|:')
    
    # Преобразование строк в целые числа
    shift = int(shift_str)
    xor_key = int(xor_key_str)

    # Обратное XOR шифрование
    shifted_back_text = ''.join(chr(ord(char) ^ xor_key) for char in encrypted_text)
    
    # Обратный сдвиг по юникоду
    decrypted_text = ''.join(chr(ord(char) - shift) for char in shifted_back_text)
    
    return decrypted_text

class User(BaseModel):
    """Модель данных пользователя для регистрации.

    Attributes:
        username (str): Уникальное имя пользователя.
        password (str): Пароль пользователя.
        key (str): Ключ шифрования для безопасного хранения данных.
    """
    username: str
    password: str
    key: str

class User_login(BaseModel):
    """Модель данных пользователя для входа.

    Attributes:
        username (str): Уникальное имя пользователя.
        password (str): Пароль пользователя.
        key (str): Ключ шифрования для безопасного хранения данных.
    """
    username: str
    password: str

class Token(BaseModel):
    """Модель данных токена доступа.

    Attributes:
        access_token (str): Токен доступа, используемый для аутентификации.
        token_type (str): Тип токена (например, "bearer").
        encryption_key (str): Ключ шифрования, связанный с токеном.
    """
    access_token: str
    token_type: str
    encryption_key: str  # Добавлено поле для ключа шифрования

class ChatMessage(BaseModel):
    """Модель данных сообщения для чата.

    Attributes:
        message (str): Текст сообщения, отправляемого в чат.
    """
    message: str

@app.on_event("startup")
async def startup_event():
    """Функция, выполняемая при запуске приложения.

    Запускает фоновые задачи для обновления IP-адреса и проверки модели.
    """
    await user_storage.connect()
    await user_storage.create_table()  # Ensure the table exists
    asyncio.create_task(upd_ip())
    asyncio.create_task(check_and_download_model())


@app.on_event("shutdown")
async def shutdown_event():
    await user_storage.close()


@app.post("/api/register", response_model=Token)
async def register(user: User):
    """
    Регистрация нового пользователя.
    
    - **username**: Имя пользователя.
    - **password**: Пароль пользователя.
    
    Возвращает токен доступа и ключ шифрования.
    """
    
    token = await user_storage.add_user(user.username, user.password, user.key)
    
    if token:
        logger.info(f"Пользователь '{user.username}' зарегистрирован.")
        encrypted_token = await encrypt(token, user.key)  # Предполагается наличие функции шифрования
        return {
            "access_token": encrypted_token,
            "token_type": "bearer",
            "encryption_key": user.key  # Возвращаем ключ шифрования
        }
    
    logger.error(f"Ошибка регистрации пользователя '{user.username}'.")
    raise HTTPException(status_code=400, detail="Ошибка регистрации.")

@app.post("/api/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Вход пользователя в систему.
    
    - **username**: Имя пользователя.
    - **password**: Пароль пользователя.
    
    Возвращает токен доступа и уникальный ключ шифрования.
    """
    
    username = form_data.username
    password = form_data.password

    token = await user_storage.verify_user(username, password)

    if not token:
        logger.error(f"Неверные учетные данные для пользователя '{username}'.")
        raise HTTPException(status_code=400, detail="Неверные учетные данные")
    
    key = await user_storage.get_key_by_token(token)  # Предполагается наличие функции получения ключа по токену

    encrypted_token = await encrypt(token, key)  # Предполагается наличие функции шифрования

    logger.info(f"Пользователь '{username}' успешно вошёл в систему.")
    
    return {
        "access_token": encrypted_token,
        "token_type": "bearer",
        "encryption_key": key
    }

async def handle_chat(token, message):

    # Проверка действительности токена
    if not await user_storage.token_exists(token):
        logger.error("Недействительный токен.")
        raise HTTPException(status_code=403, detail="Недействительный токен.")
    
    # Логгирование получения сообщения
    encryption_key = await user_storage.get_key_by_token(token)
    message = await decrypt(message.message, encryption_key)
    logger.info(f"Получено сообщение от пользователя: {message}. Токен: {token}")

    # Получение информации о пользователе
    user_info = await user_storage.get_user_by_token(token)
    user_info = user_info[1]
    logger.info(f"Информация о пользователе: {user_info}")

    result_text = ollama.generate(
        model='AURORA',
        prompt=message)['response']

    # Шифрование результатов поиска
    encrypted_results = await encrypt(result_text, encryption_key)

    return encrypted_results


@app.post("/api/chat")
async def chat(message: ChatMessage, token: str = Depends(oauth2_scheme)):
    """
    Отправка сообщения в чат и получение ответа.

    - **message**: Сообщение от пользователя.

    Возвращает ответ от модели.
    
    Проверяет действительность токена доступа.
    """
    
    bot_response = await handle_chat(token=token, message=message)

    return {
        "response": bot_response
    }

async def handle_metasearch(query, token):
    # Проверка токена
    if not user_storage.token_exists(token):
        raise HTTPException(status_code=403, detail="Недействительный токен.")
    
    usr_key = await user_storage.get_key_by_token(token)

    query = await decrypt(query, usr_key)

    # Выполнение поиска
    async def start_search():
    
        try:
            result = await meta_search(query)  # Используем query из параметра
            return result
        except Exception as e:
            logger.error(f"Ошибка: {e}")

    # Запускаем корутину
    result = await start_search()

    result = await encrypt(result, usr_key)

    return result

@app.post("/api/meta_search")
async def meta_search_endpoint(
    query: str = Query(...),  # Параметр передается через URL
    token: str = Depends(oauth2_scheme)
):
    """Эндпоинт для выполнения метапоиска.

    - **query**: Строка запроса для выполнения поиска.
    - **token**: Токен доступа для аутентификации пользователя.

    Возвращает результаты метапоиска.
    
    Проверяет действительность токена доступа перед выполнением поиска.
    """
    
    result = await handle_metasearch(query=query, token=token)
    
    return {"result": result}

@app.get("/api/file/download")
async def download_file(
    filename: str = Query(..., description="Имя файла, который необходимо загрузить."),
    token: str = Query(..., description="Зашифрованный токен доступа для аутентификации пользователя.")
):
    """
    Эндпоинт для загрузки файла.

    - **filename**: Имя файла, который необходимо загрузить.
    - **token**: Зашифрованный токен доступа для аутентификации пользователя.

    Возвращает файл в формате `application/octet-stream`.

    Проверяет действительность токена доступа перед загрузкой файла.
    """

    # Путь к локальной директории с файлами
    LOCAL_DIRECTORY = "data/filesCLIENT"

    # Проверка действительности токена
    if not token or not user_storage.token_exists(token):
        raise HTTPException(status_code=403, detail="Недействительный токен.")

    logger.info(token)

    file_path = os.path.join(LOCAL_DIRECTORY, filename)

    # Проверка существования файла
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="Файл не найден.")

    async def stream_file():
        with open(file_path, "rb") as file:
            while chunk := file.read(1024):
                yield chunk

    return StreamingResponse(stream_file(), media_type='application/octet-stream')