from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

<<<<<<< HEAD
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
    publicKey = LoadKey("assets/keys/myKeys/public_key.pem", isPublic=True)
=======
def load_key(key_path, is_public=True):
    with open(key_path, 'rb') as key_file:
        if is_public:
            return serialization.load_pem_public_key(key_file.read(), backend=default_backend())
        else:
            return serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

def test_key_pair(public_key, private_key):
    message = b'Teste de verificacao de chaves'  # Mensagem de teste
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return message == decrypted_message

# Carregar chaves
try:
    public_key = load_key("assets/keys/myKeys/public_key.pem", is_public=True)
>>>>>>> c3591dc118303abcefb04001df72d7bf1d4833e6
    print("Chave pública carregada com sucesso.")
except Exception as e:
    print(f"Erro ao carregar chave pública: {e}")

try:
<<<<<<< HEAD
    privateKey = LoadKey("assets/keys/myKeys/private_key.pem", isPublic=False)
=======
    private_key = load_key("assets/keys/myKeys/private_key.pem", is_public=False)
>>>>>>> c3591dc118303abcefb04001df72d7bf1d4833e6
    print("Chave privada carregada com sucesso.")
except Exception as e:
    print(f"Erro ao carregar chave privada: {e}")

# Testar a compatibilidade das chaves
<<<<<<< HEAD
if 'publicKey' in locals() and 'privateKey' in locals():
    if TestKeyPair(publicKey, privateKey):
=======
if 'public_key' in locals() and 'private_key' in locals():
    if test_key_pair(public_key, private_key):
>>>>>>> c3591dc118303abcefb04001df72d7bf1d4833e6
        print("As chaves são compatíveis! A criptografia e a descriptografia funcionaram corretamente.")
    else:
        print("As chaves não são compatíveis. A criptografia e a descriptografia falharam.")
