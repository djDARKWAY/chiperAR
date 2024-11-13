from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def createSignature(dataFilePath, privateKeyPath, signatureFilePath):
    with open(dataFilePath, 'rb') as f:
        data = f.read()
    with open(privateKeyPath, 'rb') as keyFile:
        privateKey = RSA.import_key(keyFile.read())
    h = SHA256.new(data)
    signature = pkcs1_15.new(privateKey).sign(h)
    with open(signatureFilePath, "wb") as sigFile:
        sigFile.write(signature)
    print("Signature created and saved successfully to:", signatureFilePath)

def verifySignature(dataFilePath, publicKeyPath, signatureFilePath):
    with open(dataFilePath, 'rb') as f:
        data = f.read()
    with open(publicKeyPath, 'rb') as keyFile:
        publicKey = RSA.import_key(keyFile.read())
    h = SHA256.new(data)
    with open(signatureFilePath, "rb") as sigFile:
        signature = sigFile.read()
    try:
        pkcs1_15.new(publicKey).verify(h, signature)
        print("Signature verified successfully!")
    except (ValueError, TypeError):
        print("Signature verification failed.")

if __name__ == "__main__":
    dataFilePath = "requirements.txt"
    privateKeyPath = "assets/keys/myKeys/privateKey.pem"
    publicKeyPath = "assets/keys/publicKeys/Jotah.pem"
    signatureFilePath = "assets/signatures/testSignature.sig"
    createSignature(dataFilePath, privateKeyPath, signatureFilePath)
    verifySignature(dataFilePath, publicKeyPath, signatureFilePath)
