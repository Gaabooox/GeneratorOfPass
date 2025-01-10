from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import random, string, pyperclip
import json

print("Bienvenido al programa de encriptación de archivos")
print("1. Encriptar archivo")
print("2. Desencriptar archivo")
print("3. Generar contraseña segura")
print("4. Salir")
opcion = int(input("Introduce el número de la opción que deseas: "))

# Función para generar una clave a partir de la contraseña
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encriptar archivo
def encrypt_file(input_filename: str, password: str):
    if not os.path.exists(input_filename):
        print(f"El archivo {input_filename} no existe. Por favor verifica el nombre del archivo.")
        return

    with open(input_filename, 'rb') as file:
        file_data = file.read()

    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Asegurarnos de que el tamaño de los datos sea múltiplo de 16
    padding_length = 16 - len(file_data) % 16
    file_data += bytes([padding_length]) * padding_length

    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    with open(input_filename, 'wb') as file:
        file.write(salt)
        file.write(iv)
        file.write(encrypted_data)

    print(f'El archivo {input_filename} ha sido encriptado y sobrescrito.')

# Desencriptar archivo
def decrypt_file(input_filename: str, password: str):
    if not os.path.exists(input_filename):
        print(f"El archivo {input_filename} no existe. Por favor verifica el nombre del archivo.")
        return

    with open(input_filename, 'rb') as file:
        salt = file.read(16)
        iv = file.read(16)
        encrypted_data = file.read()

    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        padding_length = decrypted_data[-1]
        decrypted_data = decrypted_data[:-padding_length]

        if decrypted_data:
            return decrypted_data
        else:
            raise ValueError("La contraseña es incorrecta o los datos son inválidos.")
    except Exception as e:
        print(f'Error al desencriptar el archivo: {e}')
        return None

# Generar contraseña segura    
def generate_password(length):
    if length < 10:
        print('La contraseña debe ser minimo de 10 caracteres')
        return None

    mayusculas = string.ascii_uppercase
    minisculas = string.ascii_lowercase
    digitos = string.digits
    especiales = string.punctuation

    allCaracters = mayusculas + minisculas + digitos + especiales
    password = [
        random.choice(mayusculas),
        random.choice(minisculas),
        random.choice(digitos),
        random.choice(especiales)
    ]

    password += random.choices(allCaracters, k=length-4)
    random.shuffle(password)
    return ''.join(password)

if __name__ == "__main__":
    if opcion == 1:
        # Encriptar archivo
        input_filename = input("Introduce el nombre del archivo a encriptar: ")
        while not os.path.exists(input_filename):
            print(f"El archivo {input_filename} no existe. Por favor verifica el nombre del archivo.")
            input_filename = input("Introduce el nombre del archivo a encriptar: ")

        password = input("Introduce una contraseña para encriptar el archivo: ")
        encrypt_file(input_filename, password)

    elif opcion == 2:
        # Desencriptar archivo
        input_filename = input("Introduce el nombre del archivo encriptado: ")
        while not os.path.exists(input_filename):
            print(f"El archivo {input_filename} no existe. Por favor verifica el nombre del archivo.")
            input_filename = input("Introduce el nombre del archivo encriptado: ")

        correct_password = False

        while not correct_password:
            password = input("Introduce la contraseña para desencriptar el archivo: ")
            decrypted_data = decrypt_file(input_filename, password)

            if decrypted_data is not None:
                with open(input_filename, 'wb') as file:
                    file.write(decrypted_data)
                print(f'El archivo {input_filename} ha sido desencriptado y sobrescrito.')
                correct_password = True
            else:
                print("Contraseña incorrecta, por favor intenta nuevamente.")
    
    elif opcion == 3:
        length = int(input("Introduce la longitud de la contraseña (mínimo 10 caracteres): "))
        contraseña = generate_password(length)

        if contraseña:
            pyperclip.copy(contraseña)
            print(f"Tu contraseña segura es: {contraseña}")
            print("Se ha copiado al portapapeles")
            
    elif opcion == 4:
        print("Gracias por usar el programa de encriptación de archivos.")

    else:
        print("Opción no válida.")