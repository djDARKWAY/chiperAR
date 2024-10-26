from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import os

def encryptAes256(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce + tag + ciphertext

def encryptRsa2048(data, publicKeyPath):
    with open(publicKeyPath, 'rb') as keyFile:
        public_key = RSA.import_key(keyFile.read())
    cipherRsa = PKCS1_OAEP.new(public_key)
    encryptedData = cipherRsa.encrypt(data)
    return encryptedData

def signData(data, privateKeyPath):
    with open(privateKeyPath, 'rb') as keyFile:
        private_key = RSA.import_key(keyFile.read())
    hash_data = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(hash_data)
    return signature

def main(filePath, publicKeyPath, privateKeyPath):
    # Ler dados binários do ficheiro
    with open(filePath, "rb") as file:
        data = file.read()

    # Gerar chave AES-256
    aesKey = get_random_bytes(32)  # Tamanho da chave para AES-256 é 32 bytes

    # Cifrar os dados do ficheiro com AES-256
    encryptedDataAes = encryptAes256(data, aesKey)
    encryptedAesKey = encryptRsa2048(aesKey, publicKeyPath)

    # Assinar os dados cifrados
    signature = signData(encryptedDataAes, privateKeyPath)

    # Determinar o caminho para o ambiente de trabalho
    desktopPath = os.path.join(os.path.expanduser("~"), "Desktop")

    # Criar uma pasta no ambiente de trabalho com o nome do ficheiro + (RSA)
    originalFileName = os.path.splitext(os.path.basename(filePath))[0]
    originalFileExtension = os.path.splitext(filePath)[1]
    folderName = f"{originalFileName} (RSA)"
    folderPath = os.path.join(desktopPath, folderName)
    os.makedirs(folderPath, exist_ok=True)

    # Guardar o ficheiro cifrado na nova pasta com a extensão original
    encryptedFileName = f"{originalFileName}_encrypted{originalFileExtension}"
    encryptedFilePath = os.path.join(folderPath, encryptedFileName)
    with open(encryptedFilePath, "wb") as encryptedFile:
        encryptedFile.write(encryptedDataAes)
    print(f"Encrypted file status: OK!")

    # Guardar a chave AES cifrada na nova pasta
    encryptedKeyPath = os.path.join(folderPath, "rsaKey.bin")
    with open(encryptedKeyPath, "wb") as encryptedKeyFile:
        encryptedKeyFile.write(encryptedAesKey)
    print(f"Encrypted AES key status: OK!")

    # Guardar a assinatura digital na nova pasta
    signatureFilePath = os.path.join(folderPath, "signature.bin")
    with open(signatureFilePath, "wb") as signatureFile:
        signatureFile.write(signature)
    print(f"Digital signature status: OK!")
    