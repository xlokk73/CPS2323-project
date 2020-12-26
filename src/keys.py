from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import HMAC, SHA256, SHA512


def get_master_key(master_key_part_1, master_key_part_2):
    # Returns XORed keys
    return bytes(a ^ b for (a, b) in zip(master_key_part_1, master_key_part_2))


def get_application_key():
    return get_random_bytes(16)


def encrypt_and_store(key, data, output_file):
    # Create cipher object and encrypt the data
    cipher = AES.new(key, AES.MODE_CBC)  # Create a AES cipher object with the key using the mode CBC
    ciphered_data = cipher.encrypt(pad(data, AES.block_size))  # Pad the input data and then encrypt

    file_out = open(output_file, "ab")  # Open file to write bytes
    file_out.write(cipher.iv)  # Write the iv to the output file (will be required for decryption)
    file_out.write(ciphered_data)  # Write the varying length ciphertext to the file (this is the encrypted data)
    file_out.close()


def mac_and_store(key, message, output_file):
    h = HMAC.new(key, digestmod=SHA256)
    h.update(message)
    # print(h.hexdigest())

    file_out = open(output_file, "ab")  # Open file to write bytes
    file_out.write(h.hexdigest().encode())  # Write in bytes
    file_out.close()
