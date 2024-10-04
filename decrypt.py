from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES, ChaCha20
from cryptography.hazmat.backends import default_backend
from hashVerifier import verify_hash

ALGORITHMS = {
    'AES-128': {'key_size': 16, 'algorithm': AES},
    'AES-256': {'key_size': 32, 'algorithm': AES},
    'ChaCha20': {'key_size': 32, 'algorithm': ChaCha20}
}

def decrypt_file(input_file, output_file, key, algorithm_name):
    with open(input_file, 'rb') as f:
        data = f.read()
        if algorithm_name.startswith("AES"):
            iv = data[:16]
            ciphertext = data[16:-64]
        elif algorithm_name == 'ChaCha20':
            nonce = data[:16]
            ciphertext = data[16:-64]

        hash_value_stored = data[-64:].decode()

    if algorithm_name.startswith("AES"):
        cipher = Cipher(ALGORITHMS[algorithm_name]['algorithm'](key), modes.CBC(iv), backend=default_backend())
    elif algorithm_name == 'ChaCha20':
        cipher = Cipher(ALGORITHMS[algorithm_name]['algorithm'](key, nonce), mode=None, backend=default_backend())
    
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remover padding
    padding_length = decrypted_padded[-1]
    decrypted_data = decrypted_padded[:-padding_length]

    # Verificar integridade
    if verify_hash(decrypted_data, hash_value_stored):
        print("Integrity check passed. Data is intact.")
    else:
        print("Integrity check failed. Data may be corrupted!")

    # Escrever o ficheiro descriptografado
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

    print(f"File '{input_file}' decrypted to '{output_file}'")
