import hashlib

# Função para gerar um hash a partir de uma string
def verifyHash(originalData, storedHash):
    return hashlib.sha512(originalData).hexdigest() == storedHash