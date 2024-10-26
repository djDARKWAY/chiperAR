import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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
    # Ler o conteúdo do ficheiro de entrada
    with open(inputFile, 'rb') as f:
        data = f.read()

    # Configuração do algoritmo e modo de operação
    if algorithmName.startswith("AES") or algorithmName == 'TripleDES':
        blockSize = 16 if algorithmName.startswith("AES") else 8
        iv = os.urandom(blockSize)  # Vetor de inicialização
        paddingLength = blockSize - (len(data) % blockSize)  # Calcular o padding necessário
        paddedData = data + bytes([paddingLength] * paddingLength)  # Adicionar padding
        cipher = Cipher(ALGORITHMS[algorithmName]['algorithm'](key), modes.CBC(iv), backend=default_backend())
    elif algorithmName == 'ChaCha20':
        nonce = os.urandom(16)  # Nonce para ChaCha20
        paddedData = data  # ChaCha20 não necessita de padding
        cipher = Cipher(ALGORITHMS['ChaCha20']['algorithm'](key, nonce), mode=None, backend=default_backend())

    # Encriptar os dados
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(paddedData) + encryptor.finalize()
    hashValue = hashlib.sha512(data).hexdigest()  # Calcular o hash SHA-512 dos dados originais

    # Escrever os dados encriptados no ficheiro de saída
    with open(outputFile, 'wb') as f:
        f.write(algorithmName.encode() + b'\n')
        if algorithmName.startswith("AES") or algorithmName == 'TripleDES':
            f.write(iv)
        elif algorithmName == 'ChaCha20':
            f.write(nonce)
        f.write(ciphertext)
        f.write(hashValue.encode())
