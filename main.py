import os
import subprocess
import sys
from datetime import datetime
import shutil
import keyGenerator
import encryptSy
import decryptSy
import encryptAsy
import decryptAsy
import qrcode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def installPackage(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
def uninstallPackage(package):
    subprocess.check_call([sys.executable, "-m", "pip", "uninstall", package, "-y"])
def verifyAndInstall(package):
    try:
        if package == 'Pillow':
            __import__('PIL')
        else:
            __import__(package)
    except ImportError:
        print(f"{package} not found, installing...")
        installPackage(package)
def readRequirements():
    if os.path.exists("requirements.txt"):
        with open("requirements.txt", 'r') as f:
            return [line.strip() for line in f if line.strip()]
    else:
        print(f"File 'requirements.txt' was not found! Installing manually...")
        return ['cryptography', 'qrcode', 'Pillow']
def repairDependencies():
    requiredPackages = readRequirements()

    for package in requiredPackages:
        print(f"Uninstalling package '{package}'...")
        uninstallPackage(package)
        print(f"Installing package '{package}'...")
        installPackage(package)
def chooseAlgorithm():
    print("Algorithm:\n1. AES-128\n2. AES-256\n3. TripleDES\n4. ChaCha20")
    cipherChoice = input("► ")
    return {
        '1': 'AES-128',
        '2': 'AES-256',
        '3': 'TripleDES',
        '4': 'ChaCha20'
    }.get(cipherChoice, 'AES-256')
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
def choosePublicKey():
    publicKeyDir = "assets/keys/publicKeys/"
    keys = [f for f in os.listdir(publicKeyDir) if f.endswith(".pem")]
    if not keys:
        print("No public keys found to encrypt the AES key.")
        return None

    print("Choose one of the available public keys:")
    for idx, key in enumerate(keys):
        print(f"{idx + 1}. {key}")

    try:
        choice = int(input("Choose a public key: ")) - 1
        if choice < 0 or choice >= len(keys):
            raise ValueError
    except ValueError:
        print("Invalid choice.")
        return None

    return os.path.join(publicKeyDir, keys[choice])

def main():
    while True:
        print("\n-------------- cipherAR --------------")
        print("1. Symmetric Cryptography\n2. Asymmetric Cryptography (RSA)\n3. Reverse Symmetric Encryption\n4. Reverse Asymmetric Encryption\n5. Generate Encryption Keys\n9. Fix Dependencies\n\n0. Exit")
        print("--------------------------------------")

        option = input("► ")

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

            print("Encryption key type:\n1. Generated key\n2. Custom key")
            keyChoice = input("► ")
            if keyChoice == '1':
                key = encryptSy.generateKey(cipherAlgorithm)
            elif keyChoice == '2':
                while True:
                    keyLength = 24 if cipherAlgorithm == 'TripleDES' else (16 if cipherAlgorithm == 'AES-128' else 32)
                    key = input(f"Enter your key ({keyLength} bytes for {cipherAlgorithm}):\n► ").encode()
                    if len(key) == keyLength:
                        break
                    print(f"Invalid key length for {cipherAlgorithm}. Must be {keyLength} bytes.")
            else:
                print("Invalid choice, generating key automatically...")
                key = encryptSy.generateKey(cipherAlgorithm)

            try:
                encryptSy.encryptFile(inputFile, outputFile, key, cipherAlgorithm)

                desktopPath = os.path.join(os.path.expanduser("~"), "Desktop")
                folderName = os.path.splitext(os.path.basename(outputFile))[0]
                outputDir = os.path.join(desktopPath, folderName)
                os.makedirs(outputDir, exist_ok=True)

                shutil.move(outputFile, os.path.join(outputDir, outputFile))
                print(f"Encrypted file moved to '{outputDir}/{outputFile}'.")

                saveFile(outputFile, inputFile, cipherAlgorithm, key, outputDir)

                qrFile = generateQRC(key, outputDir)
                print(f"QR Code saved as '{qrFile}'.")

            except Exception as e:
                print(f"An error occurred during encryption: {e}")
        elif option == '2':
            while True:
                inputFile = input("Enter the file name to encrypt:\n► ")
                if not os.path.isfile(inputFile):
                    print("File not found!")
                    continue
                break

            publicKeyPath = choosePublicKey()
            if not publicKeyPath:
                continue

            try:
                encryptAsy.main(filePath=inputFile, publicKeyPath=publicKeyPath)
            except Exception as e:
                print(f"An error occurred during encryption: {e}")
        elif option == '3':
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
                
                with open(inputFile, 'rb') as f:
                    algorithmName = f.readline().decode().strip()
                
                keyLength = 24 if algorithmName == 'TripleDES' else (16 if algorithmName == 'AES-128' else 32)
                if len(key) != keyLength:
                    print(f"Invalid key length. Must be {keyLength} bytes for {algorithmName}.")
                    continue

                decryptSy.decryptFile(inputFile, outputFile, key)
                print(f"File '{inputFile}' decrypted to '{outputFile}' using the detected algorithm: {algorithmName}.")
            except ValueError:
                print("Invalid key! Please enter a valid key.")
            except Exception as e:
                print(f"An error occurred during decryption: {e}")
        elif option == '4':
<<<<<<< HEAD
            privateKeyDir = "assets/keys/myKeys/"
            
            privateKeys = [f for f in os.listdir(privateKeyDir) if f.endswith(".pem")]
            
            if not privateKeys:
                print("No private keys found in 'assets/keys/myKeys/'.")
                continue

            privateKeyPath = os.path.join(privateKeyDir, "private_key.pem")
            if not os.path.isfile(privateKeyPath):
=======
            private_key_dir = "assets/keys/myKeys/"
            
            private_keys = [f for f in os.listdir(private_key_dir) if f.endswith(".pem")]
            
            if not private_keys:
                print("Nenhuma chave privada encontrada em 'assets/keys/myKeys/'.")
                continue

            private_key_path = os.path.join(private_key_dir, "private_key.pem")
            if not os.path.isfile(private_key_path):
>>>>>>> c3591dc118303abcefb04001df72d7bf1d4833e6
                print("Error: 'private_key.pem' not found!")
                print("Please create a new key pair in main menu (option 5)")
                continue

            while True:
<<<<<<< HEAD
                encryptedFileName = input("Enter the name of the encrypted file:\n► ")
                encryptedFilePath = os.path.join(os.path.expanduser("~"), "Desktop", encryptedFileName)
                
                if not os.path.isfile(encryptedFilePath):
                    print(f"Error: The encrypted file '{encryptedFileName}' was not found.")
=======
                encrypted_file_name = input("Digite o nome do ficheiro cifrado (sem extensão):\n► ") + ".bin"
                encrypted_file_path = os.path.join(os.path.expanduser("~"), "Desktop", encrypted_file_name)
                
                if not os.path.isfile(encrypted_file_path):
                    print(f"Erro: O ficheiro cifrado '{encrypted_file_name}' não foi encontrado.")
>>>>>>> c3591dc118303abcefb04001df72d7bf1d4833e6
                    continue
                break

            while True:
<<<<<<< HEAD
                encryptedKeyFileName = input("Enter the name of the encrypted AES key file (.bin):\n► ") + ".bin"
                encryptedKeyPath = os.path.join(os.path.expanduser("~"), "Desktop", encryptedKeyFileName)
                
                if not os.path.isfile(encryptedKeyPath):
                    print(f"Error: The encrypted AES key file '{encryptedKeyFileName}' was not found.")
=======
                encrypted_key_file_name = input("Digite o nome do ficheiro da chave AES cifrada (sem extensão):\n► ") + ".bin"
                encrypted_key_path = os.path.join(os.path.expanduser("~"), "Desktop", encrypted_key_file_name)
                
                if not os.path.isfile(encrypted_key_path):
                    print(f"Erro: O ficheiro da chave AES cifrada '{encrypted_key_file_name}' não foi encontrado.")
>>>>>>> c3591dc118303abcefb04001df72d7bf1d4833e6
                    continue
                break

            try:
<<<<<<< HEAD
                decryptAsy.main(encryptedFilePath, encryptedKeyPath, privateKeyPath)
            except Exception as e:
                print(f"An error occurred during decryption: {e}")
=======
                decryptAsy.main(encrypted_file_path, encrypted_key_path, private_key_path)
            except Exception as e:
                print(f"Ocorreu um erro durante a decriptação: {e}")
>>>>>>> c3591dc118303abcefb04001df72d7bf1d4833e6
        elif option == '5':
            print("Generating RSA key pair...")
            keyGenerator.generateRsaKeys()
        elif option == '9':
            print("Repairing dependencies...")
            repairDependencies()
            print("Dependencies repaired successfully.")
        elif option == '0':
            break
        else:
            print("Please select a valid option!")

if __name__ == "__main__":
    main()