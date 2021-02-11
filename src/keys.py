from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import HMAC, SHA256, SHA512


def gen_master_key_part(username, password):
    return PBKDF2(password, username, 16, count=1000000, hmac_hash_module=SHA256)


def get_master_key_part_1():
    key_file = open("mkp1.bin", "rb")
    key = key_file.read()
    key_file.close()
    return key


def get_master_key_part_2():
    key_file = open("mkp2.bin", "rb")
    key = key_file.read()
    key_file.close()
    return key


def get_key_encryption_key():
    key_file = open("kek.bin", "rb")
    key = key_file.read()
    key_file.close()
    return key


def gen_master_key(master_key_part_1, master_key_part_2):
    # Returns XORed keys
    return bytes(a ^ b for (a, b) in zip(master_key_part_1, master_key_part_2))


def gen_key_encryption_key(MK1):
    salt = b'key_encryption_key'
    return HKDF(MK1, 16, salt, SHA256, 1)


def gen_master_key_1(MK):
    salt = b'master_key_1'
    return HKDF(MK, 16, salt, SHA256, 2)[0]


def gen_master_key_2(MK):
    salt = b'master_key_2'
    return HKDF(MK, 16, salt, SHA256, 2)[1]


def verify_master_key(MK, KEK):
    return gen_key_encryption_key(gen_master_key_1(MK)) == KEK


def gen_application_key():
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
