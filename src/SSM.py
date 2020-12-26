from Crypto.Protocol.KDF import PBKDF2
from keys import *

application_keys = [gen_application_key(), gen_application_key()]

output_file = 'file_vault.bin'  # Output file
open(output_file, 'w').close()  # Clear file contents
KEK = get_key_encryption_key()  # Must be a bytes object

MK_part_1 = get_master_key_part_1()
MK_part_2 = get_master_key_part_2()

MK_1_pass = "master key 1"
MK_1 = PBKDF2(MK_1_pass, get_master_key(MK_part_1, MK_part_2), dkLen=16)

# Encrypt and store the Key Encryption Key
encrypt_and_store(MK_1, KEK, output_file)

MK_2_pass = "master key 2"
MK_2 = PBKDF2(MK_2_pass, get_master_key(MK_part_1, MK_part_2), dkLen=16)

# MAC and store the Key Encryption Key
mac_and_store(MK_2, KEK, output_file)

KEK_1_pass = "kek 1"
KEK_1 = PBKDF2(KEK_1_pass, KEK, dkLen=16)

# Encrypt and store Application Keys
for application_key in application_keys:
    encrypt_and_store(KEK_1, application_key, output_file)


KEK_2_pass = "kek 2"
KEK_2 = PBKDF2(KEK_2_pass, KEK, dkLen=16)

# MAC and store Application Keys
for application_key in application_keys:
    mac_and_store(KEK_2, application_key, output_file)
