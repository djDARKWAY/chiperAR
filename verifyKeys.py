from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def LoadKey(keyPath, isPublic=True):
    with open(keyPath, 'rb') as keyFile:
        if isPublic:
            return serialization.load_pem_public_key(keyFile.read(), backend=default_backend())
        else:
            return serialization.load_pem_private_key(keyFile.read(), password=None, backend=default_backend())

def TestKeyPair(publicKey, privateKey):
    message = b'Teste de verificacao de chaves'
    encryptedMessage = publicKey.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    decryptedMessage = privateKey.decrypt(
        encryptedMessage,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return message == decryptedMessage

try:
    publicKey = LoadKey("assets/keys/myKeys/publicKey.pem", isPublic=True)
    print("Chave pública carregada com sucesso.")
except Exception as e:
    print(f"Erro ao carregar chave pública: {e}")

try:
    privateKey = LoadKey("assets/keys/myKeys/privateKey.pem", isPublic=False)
    print("Chave privada carregada com sucesso.")
except Exception as e:
    print(f"Erro ao carregar chave privada: {e}")

# Testar a compatibilidade das chaves
if 'publicKey' in locals() and 'privateKey' in locals():
    if TestKeyPair(publicKey, privateKey):
        print("As chaves são compatíveis! A criptografia e a descriptografia funcionaram corretamente.")
    else:
        print("As chaves não são compatíveis. A criptografia e a descriptografia falharam.")
