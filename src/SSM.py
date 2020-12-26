from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Hash import HMAC, SHA256, SHA512
from keys import *

application_keys = [get_application_key(), get_application_key()]

output_file = 'file_vault.bin'  # Output file
open(output_file, 'w').close()  # Clear file contents
KEK = b'keyencryptionkey'  # Must be a bytes object

MK_part_1 = b'jfklsdjl134jkl24'
MK_part_2 = b'dsjfkldsjfkldsj4'

MK_1_pass = "master key 1"
MK_1 = PBKDF2(MK_1_pass, get_master_key(MK_part_1, MK_part_2), dkLen=16)

# Store encrypted Key Encryption Key
encrypt_and_store(MK_1, KEK, output_file)

MK_2_pass = "master key 2"
MK_2 = PBKDF2(MK_2_pass, get_master_key(MK_part_1, MK_part_2), dkLen=16)

mac_and_store(MK_2, KEK, output_file)

KEK_1_pass = "kek 1"
KEK_1 = PBKDF2(KEK_1_pass, KEK, dkLen=16)

# Store encrypted Application Keys
for application_key in application_keys:
    data = application_key  # Must be a bytes object

    encrypt_and_store(KEK_1, data, output_file)
