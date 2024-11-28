import os
import sys
import subprocess
from logo import logoPrint
from logo import version

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
import requests
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

# Funções auxiliares
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
            f"  d88P   888 888 T88b                  /_/                                   v{version}",
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
def checkUpdates(currentVersion):
    os.system('cls' if os.name == 'nt' else 'clear')
    logoPrint()
    print("Checking for updates...")
    print("--------------------------------------")
    try:
        response = requests.get("https://raw.githubusercontent.com/djDARKWAY/cipherAR/refs/heads/main/version.txt")
        latestVersion = response.text.strip()
        if currentVersion != latestVersion:
            print(f"\033[93mUpdate available: {latestVersion}. Please update your application.\033[0m")
            clearScreen()
        else:
            print("You are using the latest version.")
    except requests.RequestException as e:
        print(f"Error checking for updates: {e}")
def checkInternetConnection():
    print("Checking internet connection...")
    try:
        import urllib.request
        urllib.request.urlopen('http://google.com', timeout=5)
        print("Internet connection: OK")
        return True
    except urllib.error.URLError:
        print("No internet connection. Please check your connection and try again. Press ENTER to continue...")
        clearScreen()
        return False
# Funções de menu
def displayMenu(screen, options, currentOption, title):
    # Limpar o ecrã e esconder o cursor
    screen.clear()
    curses.curs_set(0)
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)

    # Mostrar o logo principal
    mainLogo(screen)

    # Adicionar o título do menu
    title_start_y = 10
    title_start_x = 5
    screen.addstr(title_start_y, title_start_x, title, curses.color_pair(1) | curses.A_BOLD)

    # Mostrar as opções do menu
    menuStartY = 11
    for idx, (option, description) in enumerate(options):
        # Adicionar um espaço extra antes da última opção (Exit)
        displayIdx = menuStartY + idx if idx < len(options) - 1 else menuStartY + idx + 1

        # Realçar a opção atual
        if idx == currentOption:
            screen.addstr(displayIdx, 5, f"› {description}", curses.A_REVERSE)
        else:
            screen.addstr(displayIdx, 5, f"  {description}")

    # Atualizar o ecrã
    screen.refresh()
def handleInput(key, currentOption, options):
    if key == curses.KEY_UP:
        currentOption = (currentOption - 1) % len(options)
    elif key == curses.KEY_DOWN:
        currentOption = (currentOption + 1) % len(options)
    elif key in [curses.KEY_ENTER, 10, 13]:
        return options[currentOption][0], currentOption
    elif key == 27:
        return '0', currentOption
    return None, currentOption
# Lista de menus da aplicação
def mainMenuControl():
    options = [
        ("1", "Symmetric cryptography"),
        ("2", "Asymmetric cryptography (RSA)"),
        ("3", "Decrypt symmetric encryption"),
        ("4", "Decrypt asymmetric encryption"),
        ("5", "Public keys management"),
        ("9", "Settings"),
        ("0", "Exit")
    ]
    currentOption = 0
    selectedOption = None

    def menuLogic(screen):
        nonlocal selectedOption, currentOption
        while selectedOption is None:
            displayMenu(screen, options, currentOption, "MAIN MENU")
            key = screen.getch()
            selectedOption, currentOption = handleInput(key, currentOption, options)
    curses.wrapper(menuLogic)
    return selectedOption
def publicKeysMenuControl():
    options = [
        ("1", "Add new"),
        ("2", "Delete"),
        ("3", "List all"),
        ("4", "Import zip"),
        ("5", "Export to zip"),
        ("0", "Back")
    ]
    currentOption = 0
    selectedOption = None

    def subMenuLogic(screen):
        nonlocal selectedOption, currentOption
        while selectedOption is None:
            displayMenu(screen, options, currentOption, "PUBLIC KEYS MANAGEMENT")
            key = screen.getch()
            selectedOption, currentOption = handleInput(key, currentOption, options)
    curses.wrapper(subMenuLogic)
    return selectedOption
def settingsMenuControl():
    options = [
        ("1", "Generate encryption keys"),
        ("2", "Fix dependencies"),
        ("3", "Check for updates"),
        ("0", "Back")
    ]
    currentOption = 0
    selectedOption = None

    def subMenuLogic(screen):
        nonlocal selectedOption, currentOption
        while selectedOption is None:
            displayMenu(screen, options, currentOption, "SETTINGS")
            key = screen.getch()
            selectedOption, currentOption = handleInput(key, currentOption, options)
    curses.wrapper(subMenuLogic)
    return selectedOption

os.system('cls' if os.name == 'nt' else 'clear')
checkUpdates(version)

def main():
    while True:
        # Menu principal
        option = mainMenuControl()

        # Cifrar um ficheiro com criptografia simétrica (AES, TripleDES, ChaCha20)
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
           
            # Escolha do algoritmo
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
                print(f"\033[92mEncrypted file status: OK!\033[0m")
                generateQRC(key, outputDir)
                print(f"\033[92mQR Code status: OK!\033[0m")
            except Exception as e:
                print(f"An error occurred during encryption: {e}. Press ENTER to continue...")

            # Mensagem de sucesso
            print("--------------------------------------")
            print("Encryption with AES successfully and saved in Desktop! Press ENTER to continue...")

            clearScreen()
        # Cifrar um ficheiro com criptografia assimétrica (RSA)
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
            print("Encryption with RSA successfully and saved in Desktop! Press ENTER to continue...")

            clearScreen()
        # Decifrar um ficheiro com criptografia simétrica (AES, TripleDES, ChaCha20)
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
            
            # Nome do ficheiro de saída
            originalExtension = os.path.splitext(inputFile)[1]
            outputFileName = os.path.splitext(fileName)[0] + "_decrypted" + originalExtension
            outputFile = outputFileName

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
            print("Decryption successful and saved in Desktop! Press ENTER to continue...")

            clearScreen()
        # Decifrar um ficheiro com criptografia assimétrica (RSA)
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
                print("--------------------------------------")
                print("Press ENTER to continue...")
            except Exception as e:
                print("--------------------------------------")
                print(f"An error occurred during decryption: {e}. Press ENTER to continue...")
            
            clearScreen()
        # Menu de gestão de chaves públicas
        elif option == '5':
            while True:
                # Menu de gestão de chaves públicas
                subOption = publicKeysMenuControl()

                # Adicionar uma nova chave pública
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
                # Eliminar uma chave pública
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
                # Listar todas as chaves públicas
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
                # Importar um ficheiro ZIP com chaves públicas
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
                # Exportar todas as chaves públicas para um ficheiro ZIP
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
                # Voltar ao menu principal
                elif subOption == '0':
                    break
        # Menu de configurações
        elif option == '9':
            while True:
                # Menu de configurações
                subOption = settingsMenuControl()

                # Gerar um novo par de chaves RSA
                if subOption == '1':
                    logoPrint()
                    
                    # Geração de um novo par de chaves RSA
                    print("Generating RSA key pair...")
                    keyGenerator.generateRsaKeys()
                    print("--------------------------------------")
                    print(f"RSA key pair generated successfully. Press ENTER to continue...")

                    clearScreen()
                # Reparação das dependências
                elif subOption == '2':
                    logoPrint()
                    
                    # Verificar conexão à internet
                    if not checkInternetConnection():
                        continue

                    # Reparação das dependências
                    print("Repairing dependencies...")
                    repairDependencies()
                    logoPrint()

                    # Mensagem de sucesso
                    print("Dependencies repaired successfully. Press ENTER to continue...")
                    
                    clearScreen()
                # Verificar a versão da aplicação
                elif subOption == '3':
                    logoPrint()

                    # Verificar conexão à internet
                    if not checkInternetConnection():

                        continue

                    # Verificar a versão da aplicação
                    checkUpdates(version)
                    if version == requests.get("https://raw.githubusercontent.com/djDARKWAY/cipherAR/refs/heads/main/version.txt").text.strip():
                        clearScreen()
                        continue
                # Voltar ao menu principal
                elif subOption == '0':
                    break
        # Sair da aplicação
        elif option == '0':
            os.system('cls' if os.name == 'nt' else 'clear')
            break

if __name__ == "__main__":
    main()
