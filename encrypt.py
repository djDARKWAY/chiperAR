import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES, ChaCha20
from cryptography.hazmat.backends import default_backend

ALGORITHMS = {
    'AES-128': {'keySize': 16, 'algorithm': AES},
    'AES-256': {'keySize': 32, 'algorithm': AES},
    'ChaCha20': {'keySize': 32, 'algorithm': ChaCha20}
}

# Gera uma chave com base no algoritmo de criptografia
def generateKey(algorithmName):
    keySize = ALGORITHMS[algorithmName]['keySize']
    return os.urandom(keySize)

# Cifra um ficheiro usando o algoritmo selecionado
def encryptFile(inputFile, outputFile, key, algorithmName):
    with open(inputFile, 'rb') as f:
        data = f.read()

    if algorithmName.startswith("AES"):
        iv = os.urandom(16)
        cipher = Cipher(ALGORITHMS[algorithmName]['algorithm'](key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
    elif algorithmName == 'ChaCha20':
        nonce = os.urandom(16)
        cipher = Cipher(ALGORITHMS[algorithmName]['algorithm'](key, nonce), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()

    paddingLength = 16 - (len(data) % 16)
    paddedData = data + bytes([paddingLength] * paddingLength)

    ciphertext = encryptor.update(paddedData) + encryptor.finalize()

    # Gerar o hash do conteúdo original
    hashObject = hashlib.sha512(data)
    hashValue = hashObject.hexdigest()

    # Guardar algoritmo + IV/nonce + ficheiro cifrado + hash
    with open(outputFile, 'wb') as f:
        f.write(algorithmName.encode() + b'\n')  # Adiciona o algoritmo no início
        f.write(iv if algorithmName.startswith("AES") else nonce)  # IV ou nonce no início
        f.write(ciphertext)  # Dados cifrados
        f.write(hashValue.encode())  # Hash no final

    print(f"Original File: '{inputFile}'\nEncrypted File: '{outputFile}'\nAlgorithm: {algorithmName}\nHash: '{hashValue}'")