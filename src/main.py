def get_application_key():
    return "thisistheappkey"

def get_key_encryption_key():
    return "thisisthekeyencryptionkey"

def get_master_key():
    return "thisisthemasterkey"

def encrypt(plaintext, key):
    return plaintext + "encryptedwith" + key

application_keys = [get_application_key(), get_application_key()]

vault_file = open("vault_file.txt", "w")

key_encryption_key = get_key_encryption_key()

master_key = get_master_key()

file_content = "";

# encrypt Application keys
for i in application_keys:
     file_content = file_content + "\n" + encrypt(i, key_encryption_key)

# encrypt Key Encryption Key
file_content = file_content + "\n" + encrypt(key_encryption_key, master_key)

# write to disk
vault_file.write(file_content)
