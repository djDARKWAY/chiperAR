from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def saveKeyToFile(filePath, keyData):
    with open(filePath, 'wb') as keyFile:
        keyFile.write(keyData)
    print(f"Key saved to {filePath}")

def generateRsaKeys():
    keyPair = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    keysDir = Path("assets/keys/myKeys")
    keysDir.mkdir(parents=True, exist_ok=True)

    privateKey = keyPair.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    publicKey = keyPair.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

<<<<<<< HEAD
    saveKeyToFile(keysDir / "privateKey.pem", privateKey)
    saveKeyToFile(keysDir / "publicKey.pem", publicKey)
=======
    saveKeyToFile(keysDir / "private_key.pem", privateKey)
    saveKeyToFile(keysDir / "public_key.pem", publicKey)
>>>>>>> c3591dc118303abcefb04001df72d7bf1d4833e6

    print(f"Keys generated and saved to {keysDir}")