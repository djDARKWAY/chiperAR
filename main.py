import os
import encrypt  
import decrypt  

def main():
    while True:
        print("\n---------- ChiperAR ----------")
        print("1. Encrypt with AES/ChaCha20\n2. Decrypt a file\n\n0. Exit")
        print("------------------------------")

        option = input("► ")

        if option == '1':
            while True:
                input_file = input("Enter the file name to encrypt:\n► ")
                if not os.path.isfile(input_file):
                    print("File not found!")
                    continue
                break

            # Extrair a extensão do arquivo de entrada
            file_extension = os.path.splitext(input_file)[1]

            # Mostrar a extensão para o output_file
            output_file = input(f"Output encrypted file name ({file_extension}):\n► ")
            if not output_file.endswith(file_extension):
                output_file += file_extension

            # Escolha do algoritmo de criptografia
            print("Choose encryption algorithm:\n1. AES-128\n2. AES-256\n3. ChaCha20")
            cipher_choice = input("► ")
            cipher_algorithm = 'AES-128' if cipher_choice == '1' else 'AES-256' if cipher_choice == '2' else 'ChaCha20'

            # Escolha da chave
            print("------------------\nEncryption key type:\n1. Generated key\n2. Custom key")
            key_choice = input("► ")

            if key_choice == '1':
                key = encrypt.generate_key(cipher_algorithm)
                print(f"Generated key: {key.hex()}")
            elif key_choice == '2':
                while True:
                    key_length = 16 if cipher_algorithm == 'AES-128' else 32
                    key = input(f"Enter your key ({key_length} bytes for {cipher_algorithm}):\n► ").encode()
                    if len(key) != key_length:
                        print(f"Invalid key length for {cipher_algorithm}. Must be {key_length} bytes.")
                    else:
                        break
            else:
                print("Invalid choice, generating key automatically...")
                key = encrypt.generate_key(cipher_algorithm)
                print(f"Generated key: {key.hex()}")

            # Criptografar o arquivo
            try:
                encrypt.encrypt_file(input_file, output_file, key, cipher_algorithm)
                print(f"File '{input_file}' encrypted to '{output_file}' using {cipher_algorithm}.")
            except Exception as e:
                print(f"An error occurred during encryption: {e}")

        elif option == '2':
            while True:
                input_file = input("Enter the file name to decrypt:\n► ")
                if not os.path.isfile(input_file):
                    print("File not found!")
                    continue
                break

            output_file = input(f"Output decrypted file name:\n► ")

            # Escolha o algoritmo de criptografia usado na cifragem
            print("Encryption algorithm used:\n1. AES-128\n2. AES-256\n3. ChaCha20")
            cipher_choice = input("► ")
            cipher_algorithm = 'AES-128' if cipher_choice == '1' else 'AES-256' if cipher_choice == '2' else 'ChaCha20'

            # Solicitar a chave de descriptografia
            hex_key = input(f"Enter your key:\n► ")
            try:
                key = bytes.fromhex(hex_key)
                key_length = 16 if cipher_algorithm == 'AES-128' else 32
                if len(key) != key_length:
                    print(f"Invalid key length. Must be {key_length} bytes for {cipher_algorithm}.")
                    continue

                # Descriptografar o arquivo
                decrypt.decrypt_file(input_file, output_file, key, cipher_algorithm)
                print(f"File '{input_file}' decrypted to '{output_file}' using {cipher_algorithm}.")
            except ValueError:
                print("Invalid key! Please enter a valid key.")
            except Exception as e:
                print(f"An error occurred during decryption: {e}")

        elif option == '0':
            break
        else:
            print("Please select a valid option!")

if __name__ == "__main__":
    main()