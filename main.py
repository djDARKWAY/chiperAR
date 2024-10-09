import os
import subprocess
import sys
import encrypt  
import decrypt  
from datetime import datetime
import shutil
import qrcode

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
        print(f"{package} não encontrado, instalando...")
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
    if cipherChoice == '1':
        return 'AES-128'
    elif cipherChoice == '2':
        return 'AES-256'
    elif cipherChoice == '3':
        return 'TripleDES'
    elif cipherChoice == '4':
        return 'ChaCha20'
    else:
        print("Invalid choice, defaulting to AES-128.")
        return 'AES-128'  # Default option if the choice is invalid

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

def main():
    while True:
        print("\n---------- cipherAR ----------")
        print("1. Symmetric encryption (AES/TripleDES/ChaCha20)\n2. Asymmetric encryption (RSA)\n3. Decrypt files...\n9. Repair dependencies\n\n0. Exit")
        print("------------------------------")

        option = input("► ")

        # Encrypt with AES-128, AES-256, TripleDES and ChaCha20
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
                    if cipherAlgorithm == 'TripleDES':
                        keyLength = 24  # TripleDES usa uma chave de 24 bytes
                    else:
                        keyLength = 16 if cipherAlgorithm == 'AES-128' else 32
                    key = input(f"Enter your key ({keyLength} bytes for {cipherAlgorithm}):\n► ").encode()
                    if len(key) == keyLength:
                        break
                    print(f"Invalid key length for {cipherAlgorithm}. Must be {keyLength} bytes.")
            else:
                print("Invalid choice, generating key automatically...")
                key = encrypt.generateKey(cipherAlgorithm)

            try:
                # Cifra o ficheiro e guarda na pasta temporária
                encrypt.encryptFile(inputFile, outputFile, key, cipherAlgorithm)

                # Cria uma pasta na área de trabalho
                desktopPath = os.path.join(os.path.expanduser("~"), "Desktop")
                folderName = os.path.splitext(os.path.basename(outputFile))[0]
                outputDir = os.path.join(desktopPath, folderName)
                os.makedirs(outputDir, exist_ok=True)

                # Mova o arquivo cifrado para a nova pasta
                shutil.move(outputFile, os.path.join(outputDir, outputFile))
                print(f"Encrypted file moved to '{outputDir}/{outputFile}'.")

                # Salva informações do arquivo
                saveFile(outputFile, inputFile, cipherAlgorithm, key, outputDir)

                # Gera o QR Code
                qrFile = generateQRC(key, outputDir)
                print(f"QR Code saved as '{qrFile}'.")

            except Exception as e:
                print(f"An error occurred during encryption: {e}")

        # Decrypt a file (detect algorithm)
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
                
                # Detecta o algoritmo automaticamente do arquivo
                with open(inputFile, 'rb') as f:
                    algorithmName = f.readline().decode().strip()  # Lê o nome do algoritmo do arquivo
                
                # Define o tamanho correto da chave com base no algoritmo detectado
                if algorithmName == 'TripleDES':
                    keyLength = 24  # TripleDES usa uma chave de 24 bytes
                else:
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

        # Repair dependencies
        if option == '9':
            print("Repairing dependencies...")
            repairDependencies()
            print("Dependencies repaired successfully.")

        elif option == '0':
            break
        else:
            print("Please select a valid option!")

if __name__ == "__main__":
    main()