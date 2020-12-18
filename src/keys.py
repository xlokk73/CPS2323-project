
def get_master_key():
    return "thisisthemasterkey"

def get_application_key():
    return "thisistheappkey"

def get_key_encryption_key():
    return "thisisthekeyencryptionkey"


def encrypt(plaintext, key):
    return plaintext + "encryptedwith" + key

