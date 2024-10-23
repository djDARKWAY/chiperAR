from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os

def encryptAes256(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce + tag + ciphertext

def encryptRsa2048(data, publicKeyPath):
    with open(publicKeyPath, 'rb') as key_file:
        public_key = RSA.import_key(key_file.read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher_rsa.encrypt(data)
    return encrypted_data

def main(filePath, publicKeyPath):
    # Ler dados binários do ficheiro
    with open(filePath, "rb") as file:
        data = file.read()

    # Gerar chave AES-256
    aesKey = get_random_bytes(32)  # Tamanho da chave para AES-256 é 32 bytes

    # Cifrar os dados do ficheiro com AES-256
    encryptedDataAes = encryptAes256(data, aesKey)

    # Cifrar a chave AES com RSA-2048
    encryptedAesKey = encryptRsa2048(aesKey, publicKeyPath)

    # Determinar o caminho para o ambiente de trabalho
    desktopPath = os.path.join(os.path.expanduser("~"), "Desktop")

    # Criar uma pasta no ambiente de trabalho com o nome do ficheiro + (RSA)
    originalFileName = os.path.splitext(os.path.basename(filePath))[0]
    folderName = f"{originalFileName} (RSA)"
    folderPath = os.path.join(desktopPath, folderName)
    os.makedirs(folderPath, exist_ok=True)

    # Guardar o ficheiro cifrado na nova pasta
    encryptedFileName = f"{originalFileName}.bin"
    encryptedFilePath = os.path.join(folderPath, encryptedFileName)
    with open(encryptedFilePath, "wb") as encrypted_file:
        encrypted_file.write(encryptedDataAes)
    print(f"Encrypted file saved at: {encryptedFilePath}")

    # Guardar a chave AES cifrada na nova pasta
    encryptedKeyPath = os.path.join(folderPath, "rsaKey.bin")
    with open(encryptedKeyPath, "wb") as encrypted_key_file:
        encrypted_key_file.write(encryptedAesKey)
    print(f"Encrypted AES key saved at: {encryptedKeyPath}")