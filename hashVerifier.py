import hashlib

def verify_hash(original_data, stored_hash):
    hash_object = hashlib.sha256(original_data)
    calculated_hash = hash_object.hexdigest()  # Obtém o hash em formato hexadecimal
    return calculated_hash == stored_hash
