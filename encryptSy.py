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

def generateKey(algorithmName):
    return os.urandom(ALGORITHMS[algorithmName]['keySize'])

def encryptFile(inputFile, outputFile, key, algorithmName):
    with open(inputFile, 'rb') as f:
        data = f.read()

    if algorithmName.startswith("AES") or algorithmName == 'TripleDES':
        blockSize = 16 if algorithmName.startswith("AES") else 8
        iv = os.urandom(blockSize)
        paddingLength = blockSize - (len(data) % blockSize)
        paddedData = data + bytes([paddingLength] * paddingLength)
        cipher = Cipher(ALGORITHMS[algorithmName]['algorithm'](key), modes.CBC(iv), backend=default_backend())
    elif algorithmName == 'ChaCha20':
        nonce = os.urandom(16)
        paddedData = data
        cipher = Cipher(ALGORITHMS['ChaCha20']['algorithm'](key, nonce), mode=None, backend=default_backend())

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(paddedData) + encryptor.finalize()
    hashValue = hashlib.sha512(data).hexdigest()

    with open(outputFile, 'wb') as f:
        f.write(algorithmName.encode() + b'\n')
        if algorithmName.startswith("AES") or algorithmName == 'TripleDES':
            f.write(iv)
        elif algorithmName == 'ChaCha20':
            f.write(nonce)
        f.write(ciphertext)
        f.write(hashValue.encode())

    print(f"Original File: '{inputFile}'\nEncrypted File: '{outputFile}'\nAlgorithm: {algorithmName}\nHash: '{hashValue}'")
