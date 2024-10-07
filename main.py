import os
import subprocess
import sys

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def verify_and_install(package):
    try:
        __import__(package)
    except ImportError:
        print(f"{package} não encontrado, instalando...")
        install(package)

if os.path.exists("requirements.txt"):
    with open("requirements.txt", 'r') as f:
        required_packages = [line.strip() for line in f if line.strip()]
else:
    print(f"File '{"requirements.txt"}' was not found! Instaling manually...")
    required_packages = ['cryptography', 'qrcode', 'Pillow']
    
for package in required_packages:
    verify_and_install(package)

import encrypt  
import decrypt  
from datetime import datetime
import shutil
import qrcode

def chooseAlgorithm():
    print("Algorithm:\n1. AES-128\n2. AES-256\n3. ChaCha20")
    cipher_choice = input("► ")
    return 'AES-128' if cipher_choice == '1' else 'AES-256' if cipher_choice == '2' else 'ChaCha20'

def generateQRC(key, output_dir):
    qr = qrcode.make(key.hex())
    qr_file = os.path.join(output_dir, 'QRC.png')
    qr.save(qr_file)
    return qr_file

def saveFile(output_file, input_file, cipher_algorithm, key, output_dir):
    info_file = os.path.join(output_dir, f"{os.path.splitext(output_file)[0]}_info.txt")
    with open(info_file, 'w') as f:
        f.write(f"Original File: {input_file}\n")
        f.write(f"Encrypted File: {output_file}\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Algorithm: {cipher_algorithm}\n")
        f.write(f"Key: {key.hex()}\n")
    print(f"File info saved to '{info_file}'.")

    qr_file = generateQRC(key, output_dir)

    shutil.move(output_file, os.path.join(output_dir, output_file))
    print(f"Encrypted file moved to '{output_dir}/{output_file}'.")
    print(f"QR Code saved as '{qr_file}'.")

def main():
    while True:
        print("\n---------- ChiperAR ----------")
        print("1. Encrypt with AES/ChaCha20\n2. Decrypt a file\n\n0. Exit")
        print("------------------------------")

        option = input("► ")

        # Encrypt with AES-128, AES-256 and ChaCha20
        if option == '1':
            while True:
                input_file = input("Enter the file name to encrypt:\n► ")
                if not os.path.isfile(input_file):
                    print("File not found!")
                    continue
                break

            file_extension = os.path.splitext(input_file)[1]
            output_file = input(f"Output encrypted file name ({file_extension}):\n► ")
            if not output_file.endswith(file_extension):
                output_file += file_extension

            cipher_algorithm = chooseAlgorithm()

            print("------------------\nEncryption key type:\n1. Generated key\n2. Custom key")
            key_choice = input("► ")
            if key_choice == '1':
                key = encrypt.generateKey(cipher_algorithm)
            elif key_choice == '2':
                while True:
                    key_length = 16 if cipher_algorithm == 'AES-128' else 32
                    key = input(f"Enter your key ({key_length} bytes for {cipher_algorithm}):\n► ").encode()
                    if len(key) == key_length:
                        break
                    print(f"Invalid key length for {cipher_algorithm}. Must be {key_length} bytes.")
            else:
                print("Invalid choice, generating key automatically...")
                key = encrypt.generateKey(cipher_algorithm)

            try:
                encrypt.encryptFile(input_file, output_file, key, cipher_algorithm)

                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_dir = f"encrypted_files_{timestamp}"
                os.makedirs(output_dir, exist_ok=True)

                saveFile(output_file, input_file, cipher_algorithm, key, output_dir)

            except Exception as e:
                print(f"An error occurred during encryption: {e}")

        # Decrypt a file
        elif option == '2':
            while True:
                input_file = input("Enter the file name to decrypt:\n► ")
                if not os.path.isfile(input_file):
                    print("File not found!")
                    continue
                break

            original_extension = os.path.splitext(input_file)[1]
            output_file_name = input(f"Output decrypted file name ({original_extension}):\n► ")
            output_file = f"{output_file_name}{original_extension}"

            cipher_algorithm = chooseAlgorithm()

            hex_key = input("Enter your key:\n► ")
            try:
                key = bytes.fromhex(hex_key)
                key_length = 16 if cipher_algorithm == 'AES-128' else 32
                if len(key) != key_length:
                    print(f"Invalid key length. Must be {key_length} bytes for {cipher_algorithm}.")
                    continue

                decrypt.decryptFile(input_file, output_file, key, cipher_algorithm)
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