import os
import time
from logo import logoPrint
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from tqdm import tqdm

# Função para desencriptar dados com AES-256
def decryptAes256(encryptedData, key):
    nonce = encryptedData[:16]
    tag = encryptedData[16:32]
    ciphertext = encryptedData[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)    
    chunkSize = 10 * 1024 * 1024  # 10 MB
    decryptedData = b''
    for i in tqdm(range(0, len(ciphertext), chunkSize), unit='MB', desc='Decrypting with AES-256'):
        chunk = ciphertext[i:i + chunkSize]
        decryptedData += cipher.decrypt(chunk)
    
    cipher.verify(tag)
    return decryptedData

# Função para desencriptar dados com RSA-2048
def decryptRsa2048(encryptedData, privateKeyPath):
    with open(privateKeyPath, 'rb') as keyFile:
        privateKey = RSA.import_key(keyFile.read())   
    cipherRsa = PKCS1_OAEP.new(privateKey)
    decryptedData = cipherRsa.decrypt(encryptedData)
    return decryptedData

# Função para verificar a assinatura digital e a integridade dos dados
def verifySignature(decryptedData, signaturePath, publicKeys, originalData=None):
    try:
        # Lê a assinatura digital
        with open(signaturePath, "rb") as signatureFile:
            signature = signatureFile.read()

        # Calcula o hash dos dados desencriptados
        hash_decrypted = SHA256.new(decryptedData)

        # Verifica a assinatura com cada chave pública fornecida
        for publicKeyPath in publicKeys:
            try:
                with open(publicKeyPath, 'rb') as pubKeyFile:
                    publicKey = RSA.import_key(pubKeyFile.read())

                # Verifica a assinatura
                pkcs1_15.new(publicKey).verify(hash_decrypted, signature)
                print(f"\033[92m\nSignature status: OK! ({os.path.basename(publicKeyPath)})\033[0m")
                
                # Verificação da integridade dos dados (hash de integridade)
                if originalData:
                    hash_original = SHA256.new(originalData).hexdigest()
                    if hash_original == hash_decrypted.hexdigest():
                        print("\033[92mIntegrity status: OK!\033[0m")
                        return True
                    else:
                        print("\033[91mIntegrity status: FAILED!\033[0m")

            except (ValueError, TypeError) as e:
                continue

        # Se nenhuma chave pública validar a assinatura
        print("\033[91mSignature verification failed with all available keys.\033[0m")
        return False

    except Exception as e:
        print(f"\033[91mError verifying signature: {e}\033[0m")
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

    # Desencriptar dados com a chave AES
    decryptedData = decryptAes256(encryptedDataAes, aesKey)

    # Criar uma nova pasta para o ficheiro decifrado no desktop com o nome do ficheiro
    desktopPath = os.path.join(os.path.expanduser("~"), "Desktop")
    encryptedFileName = os.path.basename(encryptedFilePath)
    decryptedFolderPath = os.path.join(desktopPath, os.path.splitext(encryptedFileName)[0])
    os.makedirs(decryptedFolderPath, exist_ok=True)

    # Determinar o nome do ficheiro original
    originalFileName = encryptedFileName.replace("_encrypted", "")
    decryptedFilePath = os.path.join(decryptedFolderPath, originalFileName)

    # Escrever os dados desencriptados para um ficheiro
    print("Writing decrypted data to file...")
    with open(decryptedFilePath, "wb") as decryptedFile:
        decryptedFile.write(decryptedData)

    # Verificação da assinatura digital e integridade dos dados
    if verifySignature(decryptedData, signaturePath, publicKeys, originalData=decryptedData):
        print("\033[92mDecryption status: OK!\033[0m")
    else:
        print("\033[91mDecryption status: OK, but signature verification failed. Nonetheless, the file was saved...\033[0m")

    # Calcular o tempo de execução
    endTime = time.time()
    elapsedTime = endTime - startTime
    hours, rem = divmod(elapsedTime, 3600)
    minutes, seconds = divmod(rem, 60)
    milliseconds = (seconds - int(seconds)) * 1000
    print(f"Time elapsed: {int(hours):02}:{int(minutes):02}:{int(seconds):02}:{int(milliseconds):03} seconds")
