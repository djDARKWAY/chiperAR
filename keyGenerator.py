from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Guardar a chave num ficheiro
def saveKeyToFile(filePath, keyData):
    with open(filePath, 'wb') as keyFile:
        keyFile.write(keyData)
    print(f"Key saved to {filePath}")

# Gerar chaves RSA e guardar na pasta assets/keys
def generateRsaKeys():
    # Gerar chave RSA
    keyPair = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Criar pasta para guardar as chaves
    keysDir = Path("assets/keys/publicKeys")
    keysDir.mkdir(parents=True, exist_ok=True)
    keysDir = Path("assets/keys/myKeys")
    keysDir.mkdir(parents=True, exist_ok=True)

    # Serializar e guardar as chaves
    privateKey = keyPair.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    publicKey = keyPair.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Guardar as chaves e respetivas Logs
    saveKeyToFile(keysDir / "privateKey.pem", privateKey)
    saveKeyToFile(keysDir / "publicKey.pem", publicKey)