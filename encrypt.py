import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES, ChaCha20
from cryptography.hazmat.backends import default_backend

ALGORITHMS = {
    'AES-128': {'key_size': 16, 'algorithm': AES},
    'AES-256': {'key_size': 32, 'algorithm': AES},
    'ChaCha20': {'key_size': 32, 'algorithm': ChaCha20}
}

# Gera uma chave com base no algoritmo de criptografia
def generateKey(algorithm_name):
    key_size = ALGORITHMS[algorithm_name]['key_size']
    return os.urandom(key_size)

# Cifra um ficheiro usando o algoritmo selecionado
def encryptFile(input_file, output_file, key, algorithm_name):
    with open(input_file, 'rb') as f:
        data = f.read()

    if algorithm_name.startswith("AES"):
        iv = os.urandom(16)
        cipher = Cipher(ALGORITHMS[algorithm_name]['algorithm'](key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
    elif algorithm_name == 'ChaCha20':
        nonce = os.urandom(16)
        cipher = Cipher(ALGORITHMS[algorithm_name]['algorithm'](key, nonce), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()

    padding_length = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_length] * padding_length)

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Gerar o hash do conteúdo original
    hash_object = hashlib.sha512(data)
    hash_value = hash_object.hexdigest()

    # Guardar IV/nonce + ficheiro cifrado + hash
    with open(output_file, 'wb') as f:
        f.write(iv if algorithm_name.startswith("AES") else nonce)  # IV ou nonce no início
        f.write(ciphertext)  # Dados cifrados
        f.write(hash_value.encode())  # Hash no final

    print(f"Original File: '{input_file}'\nEncrypted File: '{output_file}'\nAlgorithm: {algorithm_name}\n Hash: '{hash_value}'")