from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def load_public_key(public_key_path):
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def load_private_key(private_key_path):
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # Se a chave privada estiver protegida por senha, forneça aqui
            backend=default_backend()
        )
    return private_key

def test_key_pair(public_key, private_key):
    # Mensagem de teste
    message = b'Teste de verificacao de chaves'  # Codifique a mensagem como bytes

    # Criptografar com a chave pública
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Descriptografar com a chave privada
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Verifique se a mensagem original e a mensagem descriptografada são iguais
    return message == decrypted_message

# Exemplos de uso
try:
    public_key = load_public_key("assets/keys/myKeys/public_key.pem")
    print("Chave pública carregada com sucesso.")
except Exception as e:
    print(f"Erro ao carregar chave pública: {e}")

try:
    private_key = load_private_key("assets/keys/myKeys/private_key.pem")
    print("Chave privada carregada com sucesso.")
except Exception as e:
    print(f"Erro ao carregar chave privada: {e}")

# Testar a compatibilidade das chaves
if 'public_key' in locals() and 'private_key' in locals():
    if test_key_pair(public_key, private_key):
        print("As chaves são compatíveis! A criptografia e a descriptografia funcionaram corretamente.")
    else:
        print("As chaves não são compatíveis. A criptografia e a descriptografia falharam.")