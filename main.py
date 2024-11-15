import os
import sys
import subprocess
from logo import logoPrint

# Verificação das dependências
os.system('cls' if os.name == 'nt' else 'clear')
logoPrint()
print("Verifiying dependencies...")
print("--------------------------------------")
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

from datetime import datetime
import shutil
import qrcode
import zipfile
import curses
from tkinter import Tk
from tkinter.filedialog import askopenfilename
import keyGenerator
import encryptSy
import decryptSy
import encryptAsy
import decryptAsy

def repairDependencies():
    requiredPackages = readRequirements()

    for package in requiredPackages:
        print(f"Uninstalling package '{package}'...")
        uninstallPackage(package)
        print(f"Installing package '{package}'...")
        installPackage(package)
def chooseAlgorithm():
    print("Algorithm:\n1. AES-128          2. AES-256\n3. TripleDES        4. ChaCha20")
    cipherChoice = input("► ")
    algorithm = {
        '1': 'AES-128',
        '2': 'AES-256',
        '3': 'TripleDES',
        '4': 'ChaCha20'
    }.get(cipherChoice, 'AES-256')
    
    if cipherChoice not in ['1', '2', '3', '4']:
        print("Invalid choice, defaulting to AES-256.")
    
    return algorithm
def generateQRC(key, outputDir):
    qr = qrcode.make(key.hex())
    qrFile = os.path.join(outputDir, 'QRC.png')
    qr.save(qrFile)
    return qrFile
def saveFile(outputFile, inputFile, cipherAlgorithm, key, outputDir):
    infoFile = os.path.join(outputDir, f"{os.path.splitext(outputFile)[0]}-Info.txt")
    with open(infoFile, 'w') as f:
        f.write(f"Original File: {inputFile}\n")
        f.write(f"Encrypted File: {outputFile}\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Algorithm: {cipherAlgorithm}\n")
        f.write(f"Key: {key.hex()}\n")
def choosePublicKey():
    publicKeyDir = "assets/keys/publicKeys/"
    keys = [f for f in os.listdir(publicKeyDir) if f.endswith(".pem")]
    if not keys:
        print("No public keys found to encrypt the AES key.\nPress ENTER to continue...")
        clearScreen()
        return None

    print("------------- Public keys -------------")
    for idx, key in enumerate(keys):
        print(f"{idx + 1}. {key}")

    try:
        choice = int(input("Choose a public key:\n► ")) - 1
        if choice < 0 or choice >= len(keys):
            raise ValueError
    except ValueError:
        print("Invalid choice. Press ENTER to continue...")
        clearScreen()
        return None

    return os.path.join(publicKeyDir, keys[choice])
def choosePrivateKey():
    privateKeyPath = "assets/keys/myKeys/privateKey.pem"
    if not os.path.exists(privateKeyPath):
        print("Private key not found. Press ENTER to continue...")
        clearScreen()
        return None
    return privateKeyPath
def selectFile(titleName):
    root = Tk()
    root.withdraw()
    inputFile = askopenfilename(title=titleName)
    root.destroy()
    return inputFile if inputFile else None
def clearScreen():
    input()
    os.system('cls' if os.name == 'nt' else 'clear')
def mainLogo(screen):
        logoLines = [
            "       d8888 8888888b.              _______       __              ___    ____ ",
            "      d88888 888   Y88b            / ____(_)___  / /_  ___  _____/   |  / __ \\",
            "     d88P888 888    888           / /   / / __ \\/ __ \\/ _ \\/ ___/ /| | / /_/ / ",
            "    d88P 888 888   d88P          / /___/ / /_/ / / / /  __/ /  / ___ |/ _, _/  ",
            "   d88P  888 8888888P\"           \\____/_/ .___/_/ /_/\\___/_/  /_/  |_/_/ |_|   ",
            "  d88P   888 888 T88b                  /_/                                ",
            " d8888888888 888  T88b  ",
            "d88P     888 888   T88b     CipherAR: Application for Confidentiality and Integrity"
        ]
        y = 1
        x = 2
        for line in logoLines:
            screen.addstr(y, x, line, curses.color_pair(1))
            y += 1
def isNotAllowedFile(filePath):
    NOT_ALLOWED_EXTENSIONS = {'.lnk', '.exe', '.bat', '.sh', '.dll', '.sys', '.tmp'}
    fileExtension = os.path.splitext(filePath)[1].lower()
    return fileExtension in NOT_ALLOWED_EXTENSIONS
def isInvalidFileName(fileName):
    if not fileName.strip():
        return True
    if len(fileName) > 255:
        return True
    if any(ord(char) < 32 or ord(char) > 126 for char in fileName):
        return True
    return False

def menuControl():
    # Opções do menu principal
    options = [
        ("1", "Symmetric cryptography"),
        ("2", "Asymmetric cryptography (RSA)"),
        ("3", "Decrypt symmetric encryption"),
        ("4", "Decrypt asymmetric encryption"),
        ("5", "Generate encryption keys"),
        ("6", "Public keys management"),
        ("9", "Fix Dependencies"),
        ("0", "Exit")
    ]
    currentOption = 0

    # Função para chamar o logótipo principal
    curses.wrapper(mainLogo)

    # Função para desenhar o menu principal com as opções
    def displayMenu(screen):
        screen.clear()
        curses.start_color()
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        mainLogo(screen)
        menuStartY = 10
        for idx, (option, description) in enumerate(options):
            if idx == currentOption:
                screen.addstr(menuStartY + idx, 5, f"> {description}", curses.A_REVERSE)
            else:
                screen.addstr(menuStartY + idx, 5, f"  {description}")
        screen.refresh()

    # Função para lidar com a seleção de opções
    def handleInput(key):
        nonlocal currentOption
        if key == curses.KEY_UP:
            currentOption = (currentOption - 1) % len(options)
        elif key == curses.KEY_DOWN:
            currentOption = (currentOption + 1) % len(options)
        elif key in [curses.KEY_ENTER, 10, 13]:
            return options[currentOption][0]
        return None

    # Variável para armazenar a opção selecionada
    selectedOption = None

    # Função principal para controlar o menu com a respetiva lógica
    def menuLogic(screen):
        nonlocal selectedOption
        while selectedOption is None:
            displayMenu(screen)
            key = screen.getch()
            selectedOption = handleInput(key)
    curses.wrapper(menuLogic)
    return selectedOption
def subMenuControl():
    # Opções do menu principal
    options = [
        ("1", "Add new"),
        ("2", "Delete"),
        ("3", "List all"),
        ("4", "Import zip"),
        ("5", "Export to zip"),
        ("0", "Back")
    ]
    currentOption = 0

    # Função para chamar o menu secundário
    def displaySubMenu(screen):
        screen.clear()
        curses.start_color()
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        mainLogo(screen)
        menuStartY = 10
        for idx, (option, description) in enumerate(options):
            if idx == currentOption:
                screen.addstr(menuStartY + idx, 5, f"> {description}", curses.A_REVERSE)
            else:
                screen.addstr(menuStartY + idx, 5, f"  {description}")
        screen.refresh()

    # Função para lidar com a seleção de opções
    def handleSubInput(key):
        nonlocal currentOption
        if key == curses.KEY_UP:
            currentOption = (currentOption - 1) % len(options)
        elif key == curses.KEY_DOWN:
            currentOption = (currentOption + 1) % len(options)
        elif key in [curses.KEY_ENTER, 10, 13]:
            return options[currentOption][0]
        return None

    # Variável para armazenar a opção selecionada
    selectedOption = None

    # Função principal para controlar o menu com a respetiva lógica
    def subMenuLogic(screen):
        nonlocal selectedOption
        while selectedOption is None:
            displaySubMenu(screen)
            key = screen.getch()
            selectedOption = handleSubInput(key)
    curses.wrapper(subMenuLogic)
    return selectedOption

def main():
    while True:
        # Menu principal
        option = menuControl()

        if option == '1':
            logoPrint()

            # Escolha do ficheiro
            titleName = "Select a file to encrypt with symmetric cryptography"
            selectedFile = selectFile(titleName)
            if selectedFile:
                if isNotAllowedFile(selectedFile):
                    print("Selected file type is not allowed. Press ENTER to continue...")
                    clearScreen()
                    continue
                fileName = os.path.basename(selectedFile)
                if isInvalidFileName(fileName):
                    print("Invalid file name. Press ENTER to continue...")
                    clearScreen()
                    continue
                print("File to encrypt:\n►", selectedFile)
                inputFile = selectedFile
            else:
                print("File selection canceled.")
                continue
           
            # Escollha do algoritmo
            cipherAlgorithm = chooseAlgorithm()

            # Escolha do tipo de chave
            print("Encryption key type:\n1. Generated key    2. Custom key")
            keyChoice = input("► ")
            if keyChoice == '1':
                key = encryptSy.generateKey(cipherAlgorithm)
            elif keyChoice == '2':
                while True:
                    keyLength = 24 if cipherAlgorithm == 'TripleDES' else (16 if cipherAlgorithm == 'AES-128' else 32)
                    hexKey = input(f"Enter your key in hexadecimal ({keyLength * 2} hex digits for {cipherAlgorithm}):\n► ")
                    try:
                        key = bytes.fromhex(hexKey)
                        if len(key) == keyLength:
                            break
                        print(f"Invalid key length for {cipherAlgorithm}. Must be {keyLength} bytes.")
                    except ValueError:
                        print("Invalid hexadecimal key. Please enter a valid key.")
            else:
                print("Invalid choice, generating key automatically with AES-256...")
                key = encryptSy.generateKey(cipherAlgorithm)

            # Cifrar o ficheiro
            try:
                fileExtension = os.path.splitext(inputFile)[1]
                outputFile = os.path.splitext(os.path.basename(inputFile))[0] + " (" + cipherAlgorithm + ")" + fileExtension
                encryptSy.encryptFile(inputFile, outputFile, key, cipherAlgorithm)
                desktopPath = os.path.join(os.path.expanduser("~"), "Desktop")
                folderName = os.path.splitext(os.path.basename(outputFile))[0]
                outputDir = os.path.join(desktopPath, folderName)
                os.makedirs(outputDir, exist_ok=True)
                shutil.move(outputFile, os.path.join(outputDir, outputFile))
                saveFile(outputFile, inputFile, cipherAlgorithm, key, outputDir)
                print(f"Encrypted file status: OK!")
                generateQRC(key, outputDir)
                print(f"QR Code status: OK!")
            except Exception as e:
                print(f"An error occurred during encryption: {e}. Press ENTER to continue...")

            # Mensagem de sucesso
            print("--------------------------------------")
            print("Encryption with AES successful! Press ENTER to continue...")

            clearScreen()
        elif option == '2':
            logoPrint()

            # Escolha do ficheiro
            titleName = "Select a file to encrypt with asymmetric cryptography"
            selectedFile = selectFile(titleName)
            if selectedFile:
                if isNotAllowedFile(selectedFile):
                    print("Selected file type is not allowed. Press ENTER to continue...")
                    clearScreen()
                    continue
                fileName = os.path.basename(selectedFile)
                if isInvalidFileName(fileName):
                    print("Invalid file name. Press ENTER to continue...")
                    clearScreen()
                    continue
                print("File to encrypt:\n►", selectedFile)
                inputFile = selectedFile
            else:
                print("File selection canceled.")
                continue
            
            # Escolha da chave pública e privada
            publicKeyPath = choosePublicKey()
            if not publicKeyPath:
                continue
            privateKeyPath = choosePrivateKey()
            if not privateKeyPath:
                continue
            
            # Cifrar o ficheiro
            try:
                encryptAsy.main(filePath=inputFile, publicKeyPath=publicKeyPath, privateKeyPath=privateKeyPath)
            except Exception as e:
                print(f"An error occurred during encryption: {e}. Press ENTER to continue...")
                clearScreen()

            # Mensagem de sucesso
            print("--------------------------------------")
            print("Encryption with RSA successful! Press ENTER to continue...")

            clearScreen()
        elif option == '3':
            logoPrint()

            # Escolha do ficheiro
            titleName = "Select a file to decrypt with symmetric cryptography"
            selectedFile = selectFile(titleName)
            if selectedFile:
                if isNotAllowedFile(selectedFile):
                    print("Selected file type is not allowed. Press ENTER to continue...")
                    clearScreen()
                    continue
                fileName = os.path.basename(selectedFile)
                if isInvalidFileName(fileName):
                    print("Invalid file name. Press ENTER to continue...")
                    clearScreen()
                    continue
                print("File to decrypt:", selectedFile)
                inputFile = selectedFile
            else:
                print("File selection canceled.")
                continue
            
            # Escolha do nome do ficheiro de saída
            originalExtension = os.path.splitext(inputFile)[1]
            outputFileName = input(f"Choose an output decrypted file name ({originalExtension}):\n► ")
            outputFile = f"{outputFileName}{originalExtension}"

            # Procura automática da chave no ficheiro de informação ou manualmente
            infoFile = os.path.splitext(inputFile)[0] + "-Info.txt"
            if not os.path.exists(infoFile):
                print(f"Info file '{infoFile}' not found! Please enter the key manually.")
                hexKey = input("Enter your key in hexadecimal:\n► ")
                try:
                    key = bytes.fromhex(hexKey)
                except ValueError:
                    print("Invalid hexadecimal key. Please enter a valid key next time! Press ENTER to continue...")
                    continue
            else:
                try:
                    with open(infoFile, 'r') as f:
                        lines = f.readlines()
                        keyLine = next((line for line in lines if line.startswith("Key: ")), None)
                        if not keyLine:
                            print("Key not found in info file! Please enter the key manually.")
                            hexKey = input("Enter your key in hexadecimal:\n► ")
                            try:
                                key = bytes.fromhex(hexKey)
                            except ValueError:
                                print("Invalid hexadecimal key. Please enter a valid key next time! Press ENTER to continue...")
                                continue
                        else:
                            hexKey = keyLine.split("Key: ")[1].strip()
                            key = bytes.fromhex(hexKey)
                            print("Key found automatically in info file!")
                except Exception as e:
                    print(f"An error occurred while reading the info file: {e}. Press ENTER to continue...")
                    continue

            # Decifrar o ficheiro
            try:
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
            except ValueError:
                print("Invalid key! Please enter a valid key next time! Press ENTER to continue...")
                continue
            except Exception as e:
                print(f"An error occurred during decryption: {e}. Press ENTER to continue...")

            # Mensagem de sucesso
            print("--------------------------------------")
            print("Decryption successful! Press ENTER to continue...")

            clearScreen()
        elif option == '4':
            logoPrint()

            # Escolha do ficheiro
            titleName = "Select a file to decrypt with asymmetric cryptography"
            selectedFile = selectFile(titleName)
            if selectedFile:
                if isNotAllowedFile(selectedFile):
                    print("Selected file type is not allowed. Press ENTER to continue...")
                    clearScreen()
                    continue
                fileName = os.path.basename(selectedFile)
                if isInvalidFileName(fileName):
                    print("Invalid file name. Press ENTER to continue...")
                    clearScreen()
                    continue
                print("File to decrypt:\n►", selectedFile)
                encryptedFilePath = selectedFile
            else:
                print("File selection canceled.")
                continue
        
            # Procura automática da chave privada
            privateKeyDir = "assets/keys/myKeys/"
            privateKeyPath = os.path.join(privateKeyDir, "privateKey.pem")
            if not os.path.isfile(privateKeyPath):
                print("Error: 'privateKey.pem' not found!")
                print("Please create a new key pair in main menu (option 5)")
                continue

            # Procura automática do ficheiro da chave AES e da assinatura ou manualmente
            baseDir = os.path.dirname(encryptedFilePath)
            encryptedKeyPath = os.path.join(baseDir, "rsaKey.bin")
            signaturePath = os.path.join(baseDir, "signature.sig")
            if os.path.isfile(encryptedKeyPath) and os.path.isfile(signaturePath):
                print("Found 'rsaKey.bin' and 'signature.sig' automatically.")
            else:
                # Ficheiro da chave AES
                if not os.path.isfile(encryptedKeyPath):
                    titleName = "Select the encrypted AES key file (.bin)"
                    selectedFile = selectFile(titleName)
                    if selectedFile:
                        if selectedFile.endswith(".bin"):
                            print("Encrypted AES key file:\n►", selectedFile)
                            encryptedKeyPath = selectedFile
                        else:
                            print("--------------------------------------")
                            print("Only .bin files are allowed. Press ENTER to continue...")
                            clearScreen()
                            continue
                    else:
                        print("File selection canceled.")
                        continue          
                # Ficheiro da assinatura digital              
                if not os.path.isfile(signaturePath):
                    titleName = "Select the digital signature file (.sig)"
                    selectedFile = selectFile(titleName)
                    if selectedFile:
                        if selectedFile.endswith(".sig"):
                            print("Digital signature file:\n►", selectedFile)
                            signaturePath = selectedFile
                        else:
                            print("--------------------------------------")
                            print("Error: Only .sig files are allowed. Press ENTER to continue...")
                            clearScreen()
                            continue
                    else:
                        print("File selection canceled.")
                        continue

            # Lista de chaves públicas disponíveis para assinatura digital        
            publicKeyDir = "assets/keys/publicKeys/"
            publicKeys = [os.path.join(publicKeyDir, f) for f in os.listdir(publicKeyDir) if f.endswith(".pem")]
            if not publicKeys:
                print("No public keys found. Press ENTER to continue...")
                continue
            try:
                decryptAsy.main(encryptedFilePath, encryptedKeyPath, privateKeyPath, publicKeys, signaturePath)
            except Exception as e:
                print("--------------------------------------")
                print(f"An error occurred during decryption: {e}. Press ENTER to continue...")
            
            clearScreen()
        elif option == '5':
            logoPrint()
            
            # Geração de um novo par de chaves RSA
            print("Generating RSA key pair...")
            keyGenerator.generateRsaKeys()
            print("RSA key pair generated successfully.")

            clearScreen()
        elif option == '6':
            while True:
                # Menu de gestão de chaves públicas
                subOption = subMenuControl()

                if subOption == '1':
                    logoPrint()

                    # Adicionar uma nova chave pública
                    titleName = "Select a public key to add (.pem)"
                    selectedFile = selectFile(titleName)
                    if selectedFile:
                        if selectedFile.endswith(".pem"):
                            print("Public key to add:\n►", selectedFile)
                            publicKey = selectedFile
                        else:
                            print("Error: Only .pem files are allowed. Press ENTER to continue...")
                            clearScreen()
                            continue
                    else:
                        print("File selection canceled.")
                        continue
                    
                    # Copiar a chave pública para a pasta de chaves públicas
                    shutil.copy(publicKey, "assets/keys/publicKeys/")
                    print(f"Public key '{os.path.basename(publicKey)}' added successfully.")

                    clearScreen()
                elif subOption == '2':
                    logoPrint()

                    # Lista de chaves públicas disponíveis para eliminar
                    publicKeysDir = "assets/keys/publicKeys/"
                    publicKeys = [f for f in os.listdir(publicKeysDir) if f.endswith(".pem")]
                    if not publicKeys:
                        print("No public keys found. Press ENTER to continue...")
                        clearScreen()
                        continue

                    # Eliminar uma chave pública
                    print("Choose a public key to delete:")
                    for idx, key in enumerate(publicKeys):
                        print(f"{idx + 1}. {key}")
                    try:
                        choice = int(input("Choose a public key: ")) - 1
                        if choice < 0 or choice >= len(publicKeys):
                            raise ValueError
                    except ValueError:
                        print("Invalid choice. Press ENTER to continue...")
                        clearScreen()
                        continue
                    os.remove(os.path.join(publicKeysDir, publicKeys[choice]))

                    # Mensagem de sucesso
                    print(f"Public key '{publicKeys[choice]}' deleted successfully.")

                    clearScreen()
                elif subOption == '3':
                    logoPrint()

                    # Listar todas as chaves públicas
                    publicKeysDir = "assets/keys/publicKeys/"
                    publicKeys = [f for f in os.listdir(publicKeysDir) if f.endswith(".pem")]
                    if not publicKeys:
                        print("No public keys found. Press ENTER to continue...")
                        clearScreen()
                        continue
                    print("Public keys:")
                    for idx, key in enumerate(publicKeys):
                        print(f"{idx + 1}. {key}")

                    clearScreen()
                elif subOption == '4':
                    logoPrint()

                    # Importar um ficheiro ZIP com chaves públicas
                    titleName = "Select a ZIP file containing public keys"
                    selectedFile = selectFile(titleName)
                    if selectedFile:
                        print("ZIP file to import:\n►", selectedFile)
                        zipFilePath = selectedFile
                    else:
                        print("File selection canceled.")
                        continue
                    publicKeysDir = "assets/keys/publicKeys/"

                    # Extrair as chaves públicas do ficheiro ZIP
                    try:
                        with zipfile.ZipFile(zipFilePath, 'r') as zip_ref:
                            zip_ref.extractall(publicKeysDir)
                        print(f"Public keys from '{os.path.basename(zipFilePath)}' imported successfully.")
                    except Exception as e:
                        print(f"An error occurred while importing the ZIP file: {e}.")

                    clearScreen()
                elif subOption == '5':
                    logoPrint()

                    # Listar todas as chaves públicas
                    publicKeysDir = "assets/keys/publicKeys/"
                    publicKeys = [os.path.join(publicKeysDir, f) for f in os.listdir(publicKeysDir) if f.endswith(".pem")]
                    if not publicKeys:
                        print("No public keys found. Press ENTER to continue...")
                        clearScreen()
                        continue

                    # Exportar todas as chaves públicas para um ficheiro ZIP    
                    desktopPath = os.path.join(os.path.expanduser("~"), "Desktop")
                    zipFileName = os.path.join(desktopPath, "publicKeys.zip")
                    with zipfile.ZipFile(zipFileName, 'w') as zipf:
                        for key in publicKeys:
                            zipf.write(key, os.path.basename(key))
                    print(f"All public keys have been exported to your desktop successfully. Press ENTER to continue...")

                    clearScreen()
                elif subOption == '0':
                    break
        elif option == '9':
            logoPrint()
            
            # Verificar conexão à internet
            print("Checking internet connection...")
            try:
                import urllib.request
                urllib.request.urlopen('http://google.com', timeout=5)
                print("Internet connection: OK")
            except urllib.error.URLError:
                print("No internet connection. Please check your connection and try again. Press ENTER to continue...")
                clearScreen()
                continue

            # Reparação das dependências
            print("Repairing dependencies...")
            repairDependencies()
            logoPrint()

            # Mensagem de sucesso
            print("Dependencies repaired successfully. Press ENTER to continue...")
            
            clearScreen()
        elif option == '0':
            os.system('cls' if os.name == 'nt' else 'clear')
            break

if __name__ == "__main__":
    main()
