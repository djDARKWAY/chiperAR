import os
import subprocess
import sys

def installPackage(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def verifyAndInstall(package):
    try:
        if package == 'Pillow':
            __import__('PIL')
        else:
            __import__(package)
    except ImportError:
        print(f"{package} não encontrado, instalando...")
        installPackage(package)

if os.path.exists("requirements.txt"):
    with open("requirements.txt", 'r') as f:
        requiredPackages = [line.strip() for line in f if line.strip()]
else:
    print(f"File 'requirements.txt' was not found! Installing manually...")
    requiredPackages = ['cryptography', 'qrcode', 'Pillow']
    
for package in requiredPackages:
    verifyAndInstall(package)

import encrypt  
import decrypt  
from datetime import datetime
import shutil
import qrcode

def chooseAlgorithm():
    print("Algorithm:\n1. AES-128\n2. AES-256\n3. ChaCha20")
    cipherChoice = input("► ")
    return 'AES-128' if cipherChoice == '1' else 'AES-256' if cipherChoice == '2' else 'ChaCha20'

def generateQRC(key, outputDir):
    qr = qrcode.make(key.hex())
    qrFile = os.path.join(outputDir, 'QRC.png')
    qr.save(qrFile)
    return qrFile

def saveFile(outputFile, inputFile, cipherAlgorithm, key, outputDir):
    infoFile = os.path.join(outputDir, f"{os.path.splitext(outputFile)[0]}_info.txt")
    with open(infoFile, 'w') as f:
        f.write(f"Original File: {inputFile}\n")
        f.write(f"Encrypted File: {outputFile}\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Algorithm: {cipherAlgorithm}\n")
        f.write(f"Key: {key.hex()}\n")
    print(f"File info saved to '{infoFile}'.")

    qrFile = generateQRC(key, outputDir)

    shutil.move(outputFile, os.path.join(outputDir, outputFile))
    print(f"Encrypted file moved to '{outputDir}/{outputFile}'.")
    print(f"QR Code saved as '{qrFile}'.")

def main():
    while True:
        print("\n---------- cipherAR ----------")
        print("1. Encrypt with AES/ChaCha20\n2. Decrypt a file\n\n0. Exit")
        print("------------------------------")

        option = input("► ")

        # Encrypt with AES-128, AES-256 and ChaCha20
        if option == '1':
            while True:
                inputFile = input("Enter the file name to encrypt:\n► ")
                if not os.path.isfile(inputFile):
                    print("File not found!")
                    continue
                break

            fileExtension = os.path.splitext(inputFile)[1]
            outputFile = input(f"Output encrypted file name ({fileExtension}):\n► ")
            if not outputFile.endswith(fileExtension):
                outputFile += fileExtension

            cipherAlgorithm = chooseAlgorithm()

            print("------------------\nEncryption key type:\n1. Generated key\n2. Custom key")
            keyChoice = input("► ")
            if keyChoice == '1':
                key = encrypt.generateKey(cipherAlgorithm)
            elif keyChoice == '2':
                while True:
                    keyLength = 16 if cipherAlgorithm == 'AES-128' else 32
                    key = input(f"Enter your key ({keyLength} bytes for {cipherAlgorithm}):\n► ").encode()
                    if len(key) == keyLength:
                        break
                    print(f"Invalid key length for {cipherAlgorithm}. Must be {keyLength} bytes.")
            else:
                print("Invalid choice, generating key automatically...")
                key = encrypt.generateKey(cipherAlgorithm)

            try:
                encrypt.encryptFile(inputFile, outputFile, key, cipherAlgorithm)

                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                outputDir = f"encrypted_files_{timestamp}"
                os.makedirs(outputDir, exist_ok=True)

                saveFile(outputFile, inputFile, cipherAlgorithm, key, outputDir)

            except Exception as e:
                print(f"An error occurred during encryption: {e}")

        # Decrypt a file (detect algorythm)
        elif option == '2':
            while True:
                inputFile = input("Enter the file name to decrypt:\n► ")
                if not os.path.isfile(inputFile):
                    print("File not found!")
                    continue
                break

            originalExtension = os.path.splitext(inputFile)[1]
            outputFileName = input(f"Output decrypted file name ({originalExtension}):\n► ")
            outputFile = f"{outputFileName}{originalExtension}"

            hexKey = input("Enter your key:\n► ")
            try:
                key = bytes.fromhex(hexKey)
                
                # Detecta o algoritmo automaticamente do arquivo
                with open(inputFile, 'rb') as f:
                    algorithmName = f.readline().decode().strip()  # Lê o nome do algoritmo do arquivo
                
                # Define o tamanho correto da chave com base no algoritmo detectado
                keyLength = 16 if algorithmName == 'AES-128' else 32
                if len(key) != keyLength:
                    print(f"Invalid key length. Must be {keyLength} bytes for {algorithmName}.")
                    continue

                decrypt.decryptFile(inputFile, outputFile, key)
                print(f"File '{inputFile}' decrypted to '{outputFile}' using the detected algorithm: {algorithmName}.")
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