from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES, ChaCha20, TripleDES
from cryptography.hazmat.backends import default_backend
from hashVerifier import verifyHash

# Dicionário de algoritmos suportados, incluindo tamanhos de chave
ALGORITHMS = {
    'AES-128': {'keySize': 16, 'algorithm': AES},
    'AES-256': {'keySize': 32, 'algorithm': AES},
    'ChaCha20': {'keySize': 32, 'algorithm': ChaCha20},
    'TripleDES': {'keySize': 24, 'algorithm': TripleDES }
}

def decryptFile(inputFile, outputFile, key):
    # Abre o ficheiro de entrada para leitura
    with open(inputFile, 'rb') as f:
        # Lê o nome do algoritmo na primeira linha e os dados restantes
        algorithmName = f.readline().decode().strip()
        data = f.read()

    # Extraí o IV/nonce, o texto cifrado e o hash armazenado com base no algoritmo
    if algorithmName.startswith("AES"):
        iv, ciphertext, hashValueStored = data[:16], data[16:-128], data[-128:].decode()
    elif algorithmName == 'ChaCha20':
        nonce, ciphertext, hashValueStored = data[:16], data[16:-128], data[-128:].decode()
    elif algorithmName == 'TripleDES':
        iv, ciphertext, hashValueStored = data[:8], data[8:-128], data[-128:].decode()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithmName}")

    # Cria o objeto Cipher com base no algoritmo e modo apropriados
    if algorithmName.startswith("AES"):
        cipher = Cipher(ALGORITHMS[algorithmName]['algorithm'](key), modes.CBC(iv), backend=default_backend())
    elif algorithmName == 'ChaCha20':
        cipher = Cipher(ALGORITHMS['ChaCha20']['algorithm'](key, nonce), mode=None, backend=default_backend())
    elif algorithmName == 'TripleDES':
        cipher = Cipher(ALGORITHMS['TripleDES']['algorithm'](key), modes.CBC(iv), backend=default_backend())

    # Desencripta os dados
    decryptor = cipher.decryptor()
    decryptedPadded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove o padding se necessário (aplica-se a AES e TripleDES)
    if algorithmName.startswith("AES") or algorithmName == 'TripleDES':
        paddingLength = decryptedPadded[-1]  # Obtém o comprimento do padding
        decryptedData = decryptedPadded[:-paddingLength]  # Remove o padding
    else:
        decryptedData = decryptedPadded  # Para ChaCha20, não há padding

    # Verifica a integridade dos dados usando a hash armazenada
    if verifyHash(decryptedData, hashValueStored):
        print("Integrity check passed. Data is intact.")
    else:
        print("Integrity check failed. Data may be corrupted!")

    # Escreve os dados desencriptados no ficheiro de saída
    with open(outputFile, 'wb') as f:
        f.write(decryptedData)