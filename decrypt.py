from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES, ChaCha20
from cryptography.hazmat.backends import default_backend
from hashVerifier import verifyHash

ALGORITHMS = {
    'AES-128': {'keySize': 16, 'algorithm': AES},
    'AES-256': {'keySize': 32, 'algorithm': AES},
    'ChaCha20': {'keySize': 32, 'algorithm': ChaCha20}
}

def decryptFile(inputFile, outputFile, key):
    with open(inputFile, 'rb') as f:
        # Lê o algoritmo
        algorithmName = f.readline().decode().strip()

        data = f.read()
        if algorithmName.startswith("AES"):
            iv = data[:16]
            ciphertext = data[16:-128]
        elif algorithmName == 'ChaCha20':
            nonce = data[:16]
            ciphertext = data[16:-128]

        hashValueStored = data[-128:].decode()

    if algorithmName.startswith("AES"):
        cipher = Cipher(ALGORITHMS[algorithmName]['algorithm'](key), modes.CBC(iv), backend=default_backend())
    elif algorithmName == 'ChaCha20':
        cipher = Cipher(ALGORITHMS[algorithmName]['algorithm'](key, nonce), mode=None, backend=default_backend())
    
    decryptor = cipher.decryptor()
    decryptedPadded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remover padding
    paddingLength = decryptedPadded[-1]
    decryptedData = decryptedPadded[:-paddingLength]

    # Verificar integridade
    if verifyHash(decryptedData, hashValueStored):
        print("Integrity check passed. Data is intact.")
    else:
        print("Integrity check failed. Data may be corrupted!")

    # Escrever o ficheiro descriptografado
    with open(outputFile, 'wb') as f:
        f.write(decryptedData)