from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import os

def decryptAes256(encryptedData, key):
    # Extrai o nonce, o tag e o ciphertext dos dados cifrados
    nonce = encryptedData[:16]
    tag = encryptedData[16:32]
    ciphertext = encryptedData[32:]
    
    # Inicializa o objeto AES no modo EAX com o nonce fornecido
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    # Desencripta e verifica a integridade dos dados usando o tag
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

def decryptRsa2048(encryptedData, privateKeyPath):
    # Lê a chave privada a partir do ficheiro especificado
    with open(privateKeyPath, 'rb') as keyFile:
        privateKey = RSA.import_key(keyFile.read())
    
    # Inicializa o objeto RSA com a chave privada e realiza a desencriptação
    cipherRsa = PKCS1_OAEP.new(privateKey)
    decryptedData = cipherRsa.decrypt(encryptedData)
    return decryptedData

def main(encrypted_file_path, encrypted_key_path, private_key_path):
    # Lê os dados cifrados do ficheiro especificado
    with open(encrypted_file_path, "rb") as encrypted_file:
        encrypted_data_aes = encrypted_file.read()

    # Lê a chave AES cifrada do ficheiro
    with open(encrypted_key_path, "rb") as encrypted_key_file:
        encrypted_aes_key = encrypted_key_file.read()

    aes_key = decryptRsa2048(encrypted_aes_key, private_key_path)
    decrypted_data = decryptAes256(encrypted_data_aes, aes_key)
    
    # Define o caminho onde o ficheiro desencriptado será guardado
    decrypted_file_path = os.path.join(os.path.expanduser("~"), "Desktop", "picture_decrypted.jpg")
    with open(decrypted_file_path, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)
    
    print(f"Decrypted file saved at: {decrypted_file_path}")
