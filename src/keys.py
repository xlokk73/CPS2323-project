from Crypto.Random import get_random_bytes

def get_master_key():
    return get_random_bytes(16)

def get_application_key():
    return get_random_bytes(16)

def get_key_encryption_key():
    return get_random_bytes(16)


