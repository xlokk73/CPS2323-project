from keys import *
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import PBKDF2


application_keys = [get_application_key(), get_application_key()]


## Store encrypted Key Encryption Key

output_file = 'file_vault.bin' # Output file
open(output_file, 'w').close()

data = get_key_encryption_key() # Must be a bytes object

MK_1_pass = "master key 1"
key = PBKDF2(MK_1_pass, get_master_key(get_master_key_part_1(), get_master_key_part_2()), dkLen=16)

encrypt_and_store(data, key, output_file)


## Store encrypted Application Keys
for application_key in application_keys:
    data = application_key # Must be a bytes object
    key = get_key_encryption_key() # The key you generated

    encrypt_and_store(data, key, output_file)

