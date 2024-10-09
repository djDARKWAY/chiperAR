import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES, ChaCha20, TripleDES
from cryptography.hazmat.backends import default_backend

ALGORITHMS = {
    'AES-128': {'keySize': 16, 'algorithm': AES},
    'AES-256': {'keySize': 32, 'algorithm': AES},
    'ChaCha20': {'keySize': 32, 'algorithm': ChaCha20},
    'TripleDES': {'keySize': 24, 'algorithm': TripleDES }
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
        block_size = 16
        iv = os.urandom(block_size)
        paddingLength = block_size - (len(data) % block_size)
        paddedData = data + bytes([paddingLength] * paddingLength)
        cipher = Cipher(ALGORITHMS[algorithmName]['algorithm'](key), modes.CBC(iv), backend=default_backend())
    elif algorithmName == 'TripleDES':
        block_size = 8
        iv = os.urandom(block_size)
        paddingLength = block_size - (len(data) % block_size)
        paddedData = data + bytes([paddingLength] * paddingLength)
        cipher = Cipher(ALGORITHMS['TripleDES']['algorithm'](key), modes.CBC(iv), backend=default_backend())
    elif algorithmName == 'ChaCha20':
        nonce = os.urandom(16)
        paddedData = data
        cipher = Cipher(ALGORITHMS['ChaCha20']['algorithm'](key, nonce), mode=None, backend=default_backend())

    # Criação do encriptador
    encryptor = cipher.encryptor()

    # Cifra os dados
    ciphertext = encryptor.update(paddedData) + encryptor.finalize()

    # Gerar o hash do conteúdo original
    hashObject = hashlib.sha512(data)
    hashValue = hashObject.hexdigest()

    # Guardar algoritmo + IV/nonce + ficheiro cifrado + hash
    with open(outputFile, 'wb') as f:
        f.write(algorithmName.encode() + b'\n')
        if algorithmName.startswith("AES") or algorithmName == 'TripleDES':
            f.write(iv)
        elif algorithmName == 'ChaCha20':
            f.write(nonce)
        f.write(ciphertext)
        f.write(hashValue.encode())

    print(f"Original File: '{inputFile}'\nEncrypted File: '{outputFile}'\nAlgorithm: {algorithmName}\nHash: '{hashValue}'")

