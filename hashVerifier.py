import hashlib

def verifyHash(originalData, storedHash):
    hashObject = hashlib.sha512(originalData)
    calculatedHash = hashObject.hexdigest()
    return calculatedHash == storedHash