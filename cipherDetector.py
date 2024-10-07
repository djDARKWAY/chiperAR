def detectCipher(input_file):
    """Detects the encryption algorithm used in the given file."""
    with open(input_file, 'rb') as f:
        data = f.read()

    # Verifica se o arquivo é grande o suficiente
    if len(data) < 16:
        raise ValueError("File is too small to contain encryption information.")

    # O IV ou nonce ocupa os primeiros 16 bytes
    iv_nonce_length = 16  # Tamanho do IV/nonce
    algorithm_start = iv_nonce_length  # O algoritmo começa após o IV/nonce

    end_of_algorithm = data.find(b'\n', algorithm_start)

    if end_of_algorithm == -1:
        raise ValueError("Algorithm name not found in the file!")

    algorithm_name = data[algorithm_start:end_of_algorithm].decode().strip()

    # Verifica se o algoritmo é AES
    if algorithm_name.startswith("AES"):
        # Determina se é AES-128 ou AES-256 com base no tamanho da chave
        if algorithm_name == 'AES-128':
            return 'AES-128'
        elif algorithm_name == 'AES-256':
            return 'AES-256'
    elif algorithm_name == 'ChaCha20':
        return 'ChaCha20'
    
    raise ValueError("Unknown encryption method!")

if __name__ == "__main__":
    input_file = input("Enter the name of the encrypted file to detect its cipher:\n► ")
    
    try:
        algorithm = detectCipher(input_file)
        print(f"The detected encryption algorithm is: {algorithm}")
    except Exception as e:
        print(f"An error occurred: {e}")
