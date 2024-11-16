import os
import time
from logo import logoPrint
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Função para encriptar dados com AES-256
def encryptAes256(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    print(f"AES Encryption complete. Nonce: {nonce.hex()[:10]}... Tag: {tag.hex()[:10]}...")  # Depuração
    return nonce + tag + ciphertext

# Função para encriptar dados com RSA-2048
def encryptRsa2048(data, publicKeyPath):
    print(f"Loading public key from: {publicKeyPath}")
    with open(publicKeyPath, 'rb') as keyFile:
        public_key = RSA.import_key(keyFile.read())
    cipherRsa = PKCS1_OAEP.new(public_key)
    encryptedData = cipherRsa.encrypt(data)
    print(f"RSA Encryption complete. Encrypted data size: {len(encryptedData)} bytes")  # Depuração
    return encryptedData

# Função para assinar dados com chave privada RSA
def signData(data, privateKeyPath):
    print(f"Loading private key from: {privateKeyPath}")
    with open(privateKeyPath, 'rb') as keyFile:
        private_key = RSA.import_key(keyFile.read())
    hash_data = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(hash_data)
    print(f"Data signed. Signature size: {len(signature)} bytes")  # Depuração
    return signature

# Função para verificar assinatura com chave pública RSA
def verifySignature(data, signature, publicKeyPath):
    print(f"Loading public key for verification from: {publicKeyPath}")
    with open(publicKeyPath, 'rb') as keyFile:
        public_key = RSA.import_key(keyFile.read())
    hash_data = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(hash_data, signature)
        print(f"Signature verified successfully!")  # Depuração
        return True
    except (ValueError, TypeError):
        print(f"Signature verification failed!")  # Depuração
        return False

def main(filePath, publicKeyPath, privateKeyPath):
    logoPrint()
    startTime = time.time()

    # Ler dados do ficheiro
    print("Reading file data...")
    with open(filePath, "rb") as file:
        data = file.read()

    # Assinar dados antes da encriptação
    print("Signing original data...")
    signature = signData(data, privateKeyPath)

    # Gerar chave AES-256
    print("Generating AES-256 key...")
    aesKey = get_random_bytes(32)

    # Encriptar dados do ficheiro com AES-256
    print("Encrypting file data with AES-256...")
    encryptedDataAes = encryptAes256(data, aesKey)

    # Encriptar chave AES com RSA-2048
    print("Encrypting AES key with RSA-2048...")
    encryptedAesKey = encryptRsa2048(aesKey, publicKeyPath)

    # Criar diretório para guardar ficheiros encriptados e assinatura
    desktopPath = os.path.join(os.path.expanduser("~"), "Desktop")
    originalFileName = os.path.splitext(os.path.basename(filePath))[0]
    originalFileExtension = os.path.splitext(filePath)[1]
    folderName = f"{originalFileName} (RSA)"
    folderPath = os.path.join(desktopPath, folderName)
    os.makedirs(folderPath, exist_ok=True)

    # Guardar ficheiro encriptado
    encryptedFileName = f"{originalFileName}{originalFileExtension}"
    encryptedFilePath = os.path.join(folderPath, encryptedFileName)
    with open(encryptedFilePath, "wb") as encryptedFile:
        encryptedFile.write(encryptedDataAes)
    print("\033[92mEncrypted file status: OK!\033[0m")

    # Guardar chave AES encriptada
    encryptedKeyPath = os.path.join(folderPath, "rsaKey.bin")
    with open(encryptedKeyPath, "wb") as encryptedKeyFile:
        encryptedKeyFile.write(encryptedAesKey)
    print("\033[92mEncrypted AES key status: OK!\033[0m")

    # Guardar assinatura digital
    signatureFilePath = os.path.join(folderPath, "signature.sig")
    with open(signatureFilePath, "wb") as signatureFile:
        signatureFile.write(signature)  # Guardar a assinatura antes da encriptação
    print("\033[92mDigital signature status: OK!\033[0m")

    # Calcular o tempo de execução
    endTime = time.time()
    elapsedTime = endTime - startTime
    hours, rem = divmod(elapsedTime, 3600)
    minutes, seconds = divmod(rem, 60)
    milliseconds = (seconds - int(seconds)) * 1000
    print(f"Time elapsed: {int(hours):02}:{int(minutes):02}:{int(seconds):02}:{int(milliseconds):03} seconds")
