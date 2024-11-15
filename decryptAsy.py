import os
import time
from logo import logoPrint
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

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

def verifySignature(decryptedData, signaturePath, publicKeys):
    with open(signaturePath, "rb") as signatureFile:
        signature = signatureFile.read()

    hash_data = SHA256.new(decryptedData)
    print(f"Hash of decrypted data: {hash_data.hexdigest()}")  # Imprime o hash

    for publicKeyPath in publicKeys:
        try:
            print(f"Verifying signature with public key: {publicKeyPath}")
            with open(publicKeyPath, 'rb') as pubKeyFile:
                publicKey = RSA.import_key(pubKeyFile.read())

            # Verifica a assinatura
            pkcs1_15.new(publicKey).verify(hash_data, signature)
            print(f"Signature verified with public key: {publicKeyPath}")
            return True
        except (ValueError, TypeError) as e:
            print(f"Signature verification failed with public key {publicKeyPath}: {e}")
    
    print("Signature verification failed with all available public keys.")
    return False

def main(encryptedFilePath, encryptedKeyPath, privateKeyPath, publicKeys, signaturePath=None):
    logoPrint()
    startTime = time.time()

    print("Decrypting file...")
    with open(encryptedFilePath, "rb") as encryptedFile:
        encryptedDataAes = encryptedFile.read()

    with open(encryptedKeyPath, "rb") as encryptedKeyFile:
        encryptedAesKey = encryptedKeyFile.read()

    # Definir caminho padrão para assinatura se não for fornecido
    if signaturePath is None:
        signaturePath = os.path.join(os.path.dirname(encryptedFilePath), "signature.sig")

    # Tentar descriptografar usando a chave privada
    print("Decrypting AES key with private key...")
    aesKey = decryptRsa2048(encryptedAesKey, privateKeyPath)

    print("Decrypting data with AES...")
    decryptedData = decryptAes256(encryptedDataAes, aesKey)

    # Criar uma nova pasta para o ficheiro decifrado no desktop com o nome do ficheiro
    desktopPath = os.path.join(os.path.expanduser("~"), "Desktop")
    encryptedFileName = os.path.basename(encryptedFilePath)
    decryptedFolderPath = os.path.join(desktopPath, os.path.splitext(encryptedFileName)[0])
    os.makedirs(decryptedFolderPath, exist_ok=True)

    # Determinar o nome do ficheiro original
    encryptedFileName = os.path.basename(encryptedFilePath)
    originalFileName = encryptedFileName.replace("_encrypted", "")
    decryptedFilePath = os.path.join(decryptedFolderPath, originalFileName)

    print("Writing decrypted data to file...")
    with open(decryptedFilePath, "wb") as decryptedFile:
        decryptedFile.write(decryptedData)
    print("\033[92m\nDecrypted file status: OK!\033[0m")

    # Verificação da assinatura digital
    if verifySignature(decryptedData, signaturePath, publicKeys):
        print("\033[92mDecryption and signature verification successful.\033[0m")
    else:
        print("\033[91mDecryption successful, but signature verification failed. Nonetheless, the file was saved...\033[0m")

    # Calcular o tempo de execução
    endTime = time.time()
    elapsedTime = endTime - startTime
    hours, rem = divmod(elapsedTime, 3600)
    minutes, seconds = divmod(rem, 60)
    milliseconds = (seconds - int(seconds)) * 1000
    print(f"Time elapsed: {int(hours):02}:{int(minutes):02}:{int(seconds):02}:{int(milliseconds):03} seconds")
