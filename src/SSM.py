import keys
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


application_keys = [keys.get_application_key(), keys.get_application_key()]


## Store encrypted Key Encryption Key

output_file = 'file_vault.bin' # Output file
data = keys.get_key_encryption_key() # Must be a bytes object
key = keys.get_master_key() # The key you generated


# Create cipher object and encrypt the data
cipher = AES.new(key, AES.MODE_CBC) # Create a AES cipher object with the key using the mode CBC
ciphered_data = cipher.encrypt(pad(data, AES.block_size)) # Pad the input data and then encrypt


file_out = open(output_file, "wb") # Open file to write bytes
file_out.write(cipher.iv) # Write the iv to the output file (will be required for decryption)
file_out.write(ciphered_data) # Write the varying length ciphertext to the file (this is the encrypted data)
file_out.close()


## Store encrypted Application Keys
for application_key in application_keys:
    output_file = 'file_vault.bin' # Output file
    data = application_key # Must be a bytes object
    key = keys.get_key_encryption_key() # The key you generated

    # Create cipher object and encrypt the data
    cipher = AES.new(key, AES.MODE_CBC) # Create a AES cipher object with the key using the mode CBC
    ciphered_data = cipher.encrypt(pad(data, AES.block_size)) # Pad the input data and then encrypt

    file_out = open(output_file, "ab") # Open file to append bytes
    file_out.write(cipher.iv) # Write the iv to the output file (will be required for decryption)
    file_out.write(ciphered_data) # Write the varying length ciphertext to the file (this is the encrypted data)
    file_out.close()


