from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES, ChaCha20, TripleDES
from cryptography.hazmat.backends import default_backend
from hashVerifier import verifyHash
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

ALGORITHMS = {
    'AES-128': {'keySize': 16, 'algorithm': AES},
    'AES-256': {'keySize': 32, 'algorithm': AES},
    'ChaCha20': {'keySize': 32, 'algorithm': ChaCha20},
    'TripleDES': {'keySize': 24, 'algorithm': TripleDES }
}

def decryptFile(inputFile, outputFile, key):
    with open(inputFile, 'rb') as f:
        algorithmName = f.readline().decode().strip()

        data = f.read()
        if algorithmName.startswith("AES"):
            iv = data[:16]
            ciphertext = data[16:-128]
        elif algorithmName == 'ChaCha20':
            nonce = data[:16]
            ciphertext = data[16:-128]
        elif algorithmName == 'TripleDES':
            iv = data[:8]
            ciphertext = data[8:-128]

        hashValueStored = data[-128:].decode()

    # Escolhe o algoritmo apropriado
    if algorithmName.startswith("AES"):
        cipher = Cipher(ALGORITHMS[algorithmName]['algorithm'](key), modes.CBC(iv), backend=default_backend())
    elif algorithmName == 'ChaCha20':
        cipher = Cipher(ALGORITHMS['ChaCha20']['algorithm'](key, nonce), mode=None, backend=default_backend())
    elif algorithmName == 'TripleDES':
        cipher = Cipher(ALGORITHMS['TripleDES']['algorithm'](key), modes.CBC(iv), backend=default_backend())
    else:
        raise ValueError(f"Unsupported algorithm: {algorithmName}")

    decryptor = cipher.decryptor()
    decryptedPadded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remover padding (apenas para AES e TripleDES, ChaCha20 não tem padding)
    if algorithmName.startswith("AES") or algorithmName == 'TripleDES':
        paddingLength = decryptedPadded[-1]
        decryptedData = decryptedPadded[:-paddingLength]
    else:
        decryptedData = decryptedPadded

    # Verificar integridade
    if verifyHash(decryptedData, hashValueStored):
        print("Integrity check passed. Data is intact.")
    else:
        print("Integrity check failed. Data may be corrupted!")

    # Escrever o ficheiro descriptografado
    with open(outputFile, 'wb') as f:
        f.write(decryptedData)

# Decifrar com RSA e usar para descriptografar o arquivo
def rsaDecryptFile(inputFile, outputFile, privateKeyFile):
    # Carregar a chave privada RSA
    with open(privateKeyFile, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    # Ler o arquivo cifrado com RSA
    with open(inputFile, 'rb') as f:
        encryptedKey = f.read()

    # Decifrar a chave simétrica com RSA
    symmetricKey = private_key.decrypt(
    encryptedKey,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

    # Agora use a chave simétrica para decifrar o arquivo (simplesmente chamando o método de descriptografia, conforme já está implementado)
    with open(inputFile, 'rb') as f:
        algorithmName = f.readline().decode().strip()
        cipherData = f.read()

    # Use o mesmo método de descriptografia com a chave simétrica decifrada
    decryptFile(inputFile, outputFile, symmetricKey, algorithmName)
