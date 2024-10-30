from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def createSignature(dataFilePath, privateKeyPath, signatureFilePath):
    # Read the data to sign
    with open(dataFilePath, 'rb') as f:
        data = f.read()

    # Load the private key
    with open(privateKeyPath, 'rb') as keyFile:
        privateKey = RSA.import_key(keyFile.read())

    # Create the hash of the data
    h = SHA256.new(data)
    
    # Generate the signature
    signature = pkcs1_15.new(privateKey).sign(h)
    
    # Save the signature to a file
    with open(signatureFilePath, "wb") as sigFile:
        sigFile.write(signature)

    print("Signature created and saved successfully to:", signatureFilePath)

def verifySignature(dataFilePath, publicKeyPath, signatureFilePath):
    # Read the original data
    with open(dataFilePath, 'rb') as f:
        data = f.read()

    # Load the public key
    with open(publicKeyPath, 'rb') as keyFile:
        publicKey = RSA.import_key(keyFile.read())

    # Create the hash of the data
    h = SHA256.new(data)

    # Read the signature from the file
    with open(signatureFilePath, "rb") as sigFile:
        signature = sigFile.read()

    # Verify the signature
    try:
        pkcs1_15.new(publicKey).verify(h, signature)
        print("Signature verified successfully!")
    except (ValueError, TypeError):
        print("Signature verification failed.")

if __name__ == "__main__":
    # File paths
    dataFilePath = "requirements.txt"
    privateKeyPath = "assets/keys/myKeys/privateKey.pem"
    publicKeyPath = "assets/keys/publicKeys/8230465.pem"
    signatureFilePath = "assets/signatures/testSignature.sig"

    # Create the signature
    createSignature(dataFilePath, privateKeyPath, signatureFilePath)

    # Verify the signature
    verifySignature(dataFilePath, publicKeyPath, signatureFilePath)
