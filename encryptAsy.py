import os
import time
from logo import logoPrint
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

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
    logoPrint()
    startTime = time.time()

    print("Reading file data...")
    with open(filePath, "rb") as file:
        data = file.read()

    print("Generating AES-256 key...")
    aesKey = get_random_bytes(32)

    print("Encrypting file data with AES-256...")
    encryptedDataAes = encryptAes256(data, aesKey)

    print("Signing encrypted data...")
    signature = signData(encryptedDataAes, privateKeyPath)

    print("Encrypting AES key with RSA-2048...")
    encryptedAesKey = encryptRsa2048(aesKey, publicKeyPath)

    desktopPath = os.path.join(os.path.expanduser("~"), "Desktop")
    originalFileName = os.path.splitext(os.path.basename(filePath))[0]
    originalFileExtension = os.path.splitext(filePath)[1]
    folderName = f"{originalFileName} (RSA)"
    folderPath = os.path.join(desktopPath, folderName)
    os.makedirs(folderPath, exist_ok=True)

    encryptedFileName = f"{originalFileName}_encrypted{originalFileExtension}"
    encryptedFilePath = os.path.join(folderPath, encryptedFileName)
    with open(encryptedFilePath, "wb") as encryptedFile:
        encryptedFile.write(encryptedDataAes)
    print(f"\nEncrypted file status: OK!")

    encryptedKeyPath = os.path.join(folderPath, "rsaKey.bin")
    with open(encryptedKeyPath, "wb") as encryptedKeyFile:
        encryptedKeyFile.write(encryptedAesKey)
    print(f"Encrypted AES key status: OK!")

    signatureFilePath = os.path.join(folderPath, "signature.sig")
    with open(signatureFilePath, "wb") as signatureFile:
        signatureFile.write(signature)
    print(f"Digital signature status: OK!")

    endTime = time.time()
    elapsedTime = endTime - startTime
    hours, rem = divmod(elapsedTime, 3600)
    minutes, seconds = divmod(rem, 60)
    milliseconds = (seconds - int(seconds)) * 1000
    print(f"Time elapsed: {int(hours):02}:{int(minutes):02}:{int(seconds):02}:{int(milliseconds):03} seconds")
