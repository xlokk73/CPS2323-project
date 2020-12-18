import keys


application_keys = [keys.get_application_key(), keys.get_application_key()]

vault_file = open("vault_file.txt", "w")

key_encryption_key = keys.get_key_encryption_key()

master_key = keys.get_master_key()

file_content = "";

# encrypt Application keys
for i in application_keys:
     file_content = file_content + "\n" + keys.encrypt(i, key_encryption_key)

# encrypt Key Encryption Key
file_content = file_content + "\n" + keys.encrypt(key_encryption_key, master_key)

# write to disk
vault_file.write(file_content)
