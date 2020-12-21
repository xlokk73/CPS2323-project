from Crypto.Random import get_random_bytes

def get_master_key_part_1():
    return get_random_bytes(8)

def get_master_key_part_2():
    return get_random_bytes(8)

def get_master_key(master_key_part_1, master_key_part_2):
    return master_key_part_1 + master_key_part_2

def get_application_key():
    return get_random_bytes(16)

def get_key_encryption_key():
    return get_random_bytes(16)


