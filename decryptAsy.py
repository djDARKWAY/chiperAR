from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import os

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

def main(encryptedFilePath, encryptedKeyPath, privateKeyPath):
    with open(encryptedFilePath, "rb") as encryptedFile:
        encryptedDataAes = encryptedFile.read()

    with open(encryptedKeyPath, "rb") as encryptedKeyFile:
        encryptedAesKey = encryptedKeyFile.read()

    aesKey = decryptRsa2048(encryptedAesKey, privateKeyPath)
    decryptedData = decryptAes256(encryptedDataAes, aesKey)
    
    # Determinar o caminho e o nome do ficheiro original
    folderPath = os.path.dirname(encryptedFilePath)
    encryptedFileName = os.path.basename(encryptedFilePath)
    originalFileName = encryptedFileName.replace("_encrypted", "")
    decryptedFilePath = os.path.join(folderPath, originalFileName)
    
    # Substituir o ficheiro cifrado pelo ficheiro decifrado
    with open(decryptedFilePath, "wb") as decryptedFile:
        decryptedFile.write(decryptedData)
    
    print(f"Decrypted file saved at: {decryptedFilePath}")
