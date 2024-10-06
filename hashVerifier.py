import hashlib

def verifyHash(original_data, stored_hash):
    hash_object = hashlib.sha512(original_data)
    calculated_hash = hash_object.hexdigest()
    return calculated_hash == stored_hash
