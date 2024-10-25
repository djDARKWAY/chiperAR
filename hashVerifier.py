import hashlib

def verifyHash(originalData, storedHash):
    return hashlib.sha512(originalData).hexdigest() == storedHash