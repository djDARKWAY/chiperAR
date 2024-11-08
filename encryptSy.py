import os
import hashlib
import time
from logo import logoPrint
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES, ChaCha20, TripleDES
from cryptography.hazmat.backends import default_backend

# Dicionário que mapeia os nomes dos algoritmos para os seus tamanhos de chave e classes correspondentes
ALGORITHMS = {
    'AES-128': {'keySize': 16, 'algorithm': AES},
    'AES-256': {'keySize': 32, 'algorithm': AES},
    'ChaCha20': {'keySize': 32, 'algorithm': ChaCha20},
    'TripleDES': {'keySize': 24, 'algorithm': TripleDES }
}

# Função para gerar uma chave aleatória com base no algoritmo escolhido
def generateKey(algorithmName):
    return os.urandom(ALGORITHMS[algorithmName]['keySize'])

# Função para encriptar um ficheiro
def encryptFile(inputFile, outputFile, key, algorithmName):
    logoPrint()
    startTime = time.time()

    # Ler o conteúdo do ficheiro de entrada
    print("Reading input file...")
    with open(inputFile, 'rb') as f:
        data = f.read()

    # Configuração do algoritmo e modo de operação
    print("Configuring cipher...")
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

    # Encriptar os dados
    print("Encrypting file...")
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(paddedData) + encryptor.finalize()
    print("Creating hash...")
    hashValue = hashlib.sha512(data).hexdigest()

    # Escrever os dados encriptados no ficheiro de saída
    print("Writing to output file...")
    with open(outputFile, 'wb') as f:
        f.write(algorithmName.encode() + b'\n')
        if algorithmName.startswith("AES") or algorithmName == 'TripleDES':
            f.write(iv)
        elif algorithmName == 'ChaCha20':
            f.write(nonce)
        f.write(ciphertext)
        f.write(hashValue.encode())

    endTime = time.time()
    elapsedTime = endTime - startTime
    hours, rem = divmod(elapsedTime, 3600)
    minutes, seconds = divmod(rem, 60)
    milliseconds = (seconds - int(seconds)) * 1000
    print(f"\nTime elapsed: {int(hours):02}:{int(minutes):02}:{int(seconds):02}:{int(milliseconds):03} seconds")
