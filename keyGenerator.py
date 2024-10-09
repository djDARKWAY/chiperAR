import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def saveKeyToFile(filePath, keyData):
    with open(filePath, 'wb') as keyFile:
        keyFile.write(keyData)
    print(f"Key saved to {filePath}")

def generateRsaKeys():
    # Gera um par de chaves RSA (2048 bits)
    keyPair = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    myKeysDir = Path("assets/keys/myKeys")
    myKeysDir.mkdir(parents=True, exist_ok=True)

    privateKeyFile = myKeysDir / "private_key.pem"
    privateKey = keyPair.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    publicKeyFile = myKeysDir / "public_key.pem"
    publicKey = keyPair.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    saveKeyToFile(privateKeyFile, privateKey)
    saveKeyToFile(publicKeyFile, publicKey)

    print(f"Keys generated and saved to {myKeysDir}")

# Verifica se o script está sendo executado diretamente
if __name__ == "__main__":
    generateRsaKeys()