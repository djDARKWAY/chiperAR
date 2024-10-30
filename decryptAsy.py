from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os
import time

def decryptAes256(encryptedData, key):
    nonce = encryptedData[:16]
    tag = encryptedData[16:32]
    ciphertext = encryptedData[32:]
    
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

def decryptRsa2048(encryptedData, privateKeyPath):
    with open(privateKeyPath, 'rb') as keyFile:
        privateKey = RSA.import_key(keyFile.read())
    
    cipherRsa = PKCS1_OAEP.new(privateKey)
    decryptedData = cipherRsa.decrypt(encryptedData)
    return decryptedData

def verifySignature(publicKeyPath, data, signature):
    with open(publicKeyPath, 'rb') as keyFile:
        publicKey = RSA.import_key(keyFile.read())
    
    h = SHA256.new(data)
    try:
        pkcs1_15.new(publicKey).verify(h, signature)
        print("Signature verified successfully.")
    except (ValueError, TypeError):
        print("Signature verification failed.")

def main(encryptedFilePath, encryptedKeyPath, privateKeyPath, signaturePath, publicKeyPath):
    os.system('cls' if os.name == 'nt' else 'clear')
    print("Decrypting file...")
    startTime = time.time()

    with open(encryptedFilePath, "rb") as encryptedFile:
        encryptedDataAes = encryptedFile.read()

    with open(encryptedKeyPath, "rb") as encryptedKeyFile:
        encryptedAesKey = encryptedKeyFile.read()

    print("Decrypting AES key with RSA...")
    aesKey = decryptRsa2048(encryptedAesKey, privateKeyPath)

    print("Decrypting data with AES...")
    decryptedData = decryptAes256(encryptedDataAes, aesKey)

    with open(signaturePath, "rb") as signatureFile:
        signature = signatureFile.read()
    print("Verifying signature...")
    verifySignature(publicKeyPath, decryptedData, signature)
    
    # Determinar o caminho e o nome do ficheiro original
    folderPath = os.path.dirname(encryptedFilePath)
    encryptedFileName = os.path.basename(encryptedFilePath)
    originalFileName = encryptedFileName.replace("_encrypted", "")
    decryptedFilePath = os.path.join(folderPath, originalFileName)
    
    print("Writing decrypted data to file...")
    # Substituir o ficheiro cifrado pelo ficheiro decifrado
    with open(decryptedFilePath, "wb") as decryptedFile:
        decryptedFile.write(decryptedData)
        
    # Apagar o ficheiro cifrado
    os.remove(encryptedFilePath)    
    print(f"\nDecrypted file status: OK!")

    endTime = time.time()
    elapsedTime = endTime - startTime
    hours, rem = divmod(elapsedTime, 3600)
    minutes, seconds = divmod(rem, 60)
    milliseconds = (seconds - int(seconds)) * 1000
    print(f"Time elapsed: {int(hours):02}:{int(minutes):02}:{int(seconds):02}:{int(milliseconds):03} seconds")