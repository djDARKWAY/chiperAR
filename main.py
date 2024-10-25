import os
import subprocess
import sys
from datetime import datetime

def readRequirements():
    with open("requirements.txt", "r") as f:
        return f.read().splitlines()
def installPackage(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
def uninstallPackage(package):
    subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "-y", package])

requiredPackages = readRequirements()
for package in requiredPackages:
    try:
        __import__(package)
    except ImportError:
        installPackage(package)

import shutil
import keyGenerator
import encryptSy
import decryptSy
import encryptAsy
import decryptAsy
import qrcode
from tkinter import Tk
from tkinter.filedialog import askopenfilename

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
def choosePrivateKey():
    privateKeyPath = "assets/keys/myKeys/privateKey.pem"
    if not os.path.exists(privateKeyPath):
        print("Private key not found.")
        return None
    return privateKeyPath
def selectFile(titleName):
    root = Tk()
    root.withdraw()
    inputFile = askopenfilename(title=titleName)
    root.destroy()
    return inputFile if inputFile else None

def main():
    while True:
        print("\n-------------- cipherAR --------------")
        print("1. Symmetric Cryptography\n2. Asymmetric Cryptography (RSA)\n3. Reverse Symmetric Encryption\n4. Reverse Asymmetric Encryption\n5. Generate Encryption Keys\n9. Fix Dependencies\n\n0. Exit")
        print("--------------------------------------")
        option = input("► ")

        if option == '1':
            titleName = "Select a file to encrypt with symmetric cryptography"
            selectedFile = selectFile(titleName)
            if selectedFile:
                print("File to encrypt:", selectedFile)
                inputFile = selectedFile
            else:
                print("File selection canceled.")
                continue

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
            titleName = "Select a file to encrypt with asymmetric cryptography"
            selectedFile = selectFile(titleName)
            if selectedFile:
                print("File to encrypt:", selectedFile)
                inputFile = selectedFile
            else:
                print("File selection canceled.")
                continue

            publicKeyPath = choosePublicKey()
            if not publicKeyPath:
                continue

            privateKeyPath = choosePrivateKey()
            if not privateKeyPath:
                continue

            try:
                encryptAsy.main(filePath=inputFile, publicKeyPath=publicKeyPath, privateKeyPath=privateKeyPath)
            except Exception as e:
                print(f"An error occurred during encryption: {e}")
        elif option == '3':
            titleName = "Select a file to decrypt with symmetric cryptography"
            selectedFile = selectFile(titleName)
            if selectedFile:
                print("File to decrypt:", selectedFile)
                inputFile = selectedFile
            else:
                print("File selection canceled.")
                continue

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

                desktopPath = os.path.join(os.path.expanduser("~"), "Desktop")
                outputDir = os.path.join(desktopPath, os.path.splitext(os.path.basename(outputFile))[0])
                os.makedirs(outputDir, exist_ok=True)

                shutil.move(outputFile, os.path.join(outputDir, outputFile))
                print(f"Decrypted file moved to '{outputDir}/{outputFile}' using the detected algorithm: {algorithmName}.")
            except ValueError:
                print("Invalid key! Please enter a valid key.")
            except Exception as e:
                print(f"An error occurred during decryption: {e}")
        elif option == '4':
            privateKeyDir = "assets/keys/myKeys/"
            privateKeyPath = os.path.join(privateKeyDir, "privateKey.pem")

            # Check if the private key exists
            if not os.path.isfile(privateKeyPath):
                print("Error: 'privateKey.pem' not found!")
                print("Please create a new key pair in main menu (option 5)")
                continue

            titleName = "Select a file to decrypt with asymmetric cryptography"
            selectedFile = selectFile(titleName)
            if selectedFile:
                print("File to decrypt:", selectedFile)
                encryptedFilePath = selectedFile
            else:
                print("File selection canceled.")
                continue

            # Automatically look for rsaKey.bin and signature.bin in the same directory
            baseDir = os.path.dirname(encryptedFilePath)
            encryptedKeyPath = os.path.join(baseDir, "rsaKey.bin")
            signaturePath = os.path.join(baseDir, "signature.bin")

            if os.path.isfile(encryptedKeyPath) and os.path.isfile(signaturePath):
                print("Found 'rsaKey.bin' and 'signature.bin' automatically.")
            else:
                if not os.path.isfile(encryptedKeyPath):
                    titleName = "Select the encrypted AES key file (.bin)"
                    selectedFile = selectFile(titleName)
                    if selectedFile:
                        print("Encrypted AES key file:", selectedFile)
                        encryptedKeyPath = selectedFile
                    else:
                        print("File selection canceled.")
                        continue

                if not os.path.isfile(signaturePath):
                    titleName = "Select the digital signature file"
                    selectedFile = selectFile(titleName)
                    if selectedFile:
                        print("Digital signature file:", selectedFile)
                        signaturePath = selectedFile
                    else:
                        print("File selection canceled.")
                        continue

            # Path to public keys
            publicKeyDir = "assets/keys/publicKeys/"
            publicKeys = [os.path.join(publicKeyDir, f) for f in os.listdir(publicKeyDir) if f.endswith(".pem")]

            if not publicKeys:
                print("No public keys found.")
                continue

            decryptionSuccessful = False
            for publicKeyPath in publicKeys:
                try:
                    decryptAsy.main(encryptedFilePath, encryptedKeyPath, privateKeyPath, signaturePath, publicKeyPath)
                    print(f"Decryption successful with public key: {publicKeyPath}")
                    decryptionSuccessful = True
                    break
                except Exception as e:
                    print(f"An error occurred with public key {publicKeyPath}: {e}")

            if not decryptionSuccessful:
                print("Decryption failed with all available public keys.")
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
