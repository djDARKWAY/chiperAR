import subprocess

def getModulus(filePath, isPublic):
    command = ["openssl", "rsa"]
    if isPublic:
        command.extend(["-pubin", "-in", filePath, "-modulus", "-noout"])
    else:
        command.extend(["-in", filePath, "-modulus", "-noout"])
    
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise Exception(f"Error executing command: {result.stderr}")
    
    modulusLine = result.stdout.strip()
    modulus = modulusLine.split('=')[1]
    return modulus

def verifyKeys(publicKeyPath, privateKeyPath):
    publicModulus = getModulus(publicKeyPath, isPublic=True)
    privateModulus = getModulus(privateKeyPath, isPublic=False)
    
    if publicModulus == privateModulus:
        print("The key pair is functional.")
    else:
        print("The key pair is not functional.")

if __name__ == "__main__":
    publicKeyPath = "assets/keys/myKeys/publicKey.pem"
    privateKeyPath = "assets/keys/myKeys/privateKey.pem"
    verifyKeys(publicKeyPath, privateKeyPath)