import os
import time
from logo import logoPrint
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import hashlib

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

def verifySignature(decryptedData, signaturePath, publicKeys, originalData=None):
    try:
        # Lê a assinatura digital
        with open(signaturePath, "rb") as signatureFile:
            signature = signatureFile.read()

        print(f"Assinatura lida (tamanho: {len(signature)}): {signature.hex()}")

        # Calcula o hash dos dados desencriptados
        hash_data = SHA256.new(decryptedData)
        print(f"Hash dos dados desencriptografados: {hash_data.hexdigest()}")

        # Verifica a assinatura com cada chave pública fornecida
        for publicKeyPath in publicKeys:
            try:
                print(f"Tentativa de verificação com a chave pública: {publicKeyPath}")
                with open(publicKeyPath, 'rb') as pubKeyFile:
                    publicKey = RSA.import_key(pubKeyFile.read())

                # Verifica a assinatura
                pkcs1_15.new(publicKey).verify(hash_data, signature)
                print(f"\033[92mAssinatura verificada com sucesso com a chave pública: {publicKeyPath}\033[0m")
                
                # Verificação da integridade dos dados (hash de integridade)
                if originalData:
                    hash_original = hashlib.sha256(originalData).hexdigest()
                    if hash_original == hash_data.hexdigest():
                        print("\033[92mIntegridade verificada com sucesso. Os dados não foram alterados.\033[0m")
                    else:
                        print("\033[91mFalha na verificação de integridade. Os dados foram alterados.\033[0m")

                return True  # Retorna sucesso na primeira verificação válida
            except (ValueError, TypeError) as e:
                print(f"\033[93mFalha na verificação com a chave pública {publicKeyPath}: {e}\033[0m")

        # Se nenhuma chave pública validar a assinatura
        print("\033[91mFalha na verificação da assinatura com todas as chaves disponíveis.\033[0m")
        return False

    except Exception as e:
        print(f"\033[91mErro ao verificar a assinatura: {e}\033[0m")
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
    originalFileName = encryptedFileName.replace("_encrypted", "")
    decryptedFilePath = os.path.join(decryptedFolderPath, originalFileName)

    print("Writing decrypted data to file...")
    with open(decryptedFilePath, "wb") as decryptedFile:
        decryptedFile.write(decryptedData)
    print("\033[92m\nDecrypted file status: OK!\033[0m")

    # Verificação da assinatura digital e integridade dos dados
    with open(encryptedFilePath, "rb") as originalFile:
        originalData = originalFile.read()

    if verifySignature(decryptedData, signaturePath, publicKeys, originalData=originalData):
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
