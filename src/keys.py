from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import HMAC, SHA256, SHA512


def gen_master_key_part(username, password):
    salt = b'=\xe3L6d\xc1\xb4:\x8e\xfe\x15\x04K\x07L\xd5'
    return PBKDF2(username + password, salt, 16, count=1000000, hmac_hash_module=SHA256)


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
    salt = b'#B\xb2\xcb\xfa\xf9hZ\x9d[\xc4>\xc9\xe8\x0bK'
    return HKDF(MK1, 16, salt, SHA256, 1)


def gen_master_key_1(MK):
    salt = b';D\x8d6^\x88\xc5\x89\x86\x03\xf77\x9c2*\x1b'
    return HKDF(MK, 16, salt, SHA256, 2)[0]


def gen_master_key_2(MK):
    salt = b';D\x8d6^\x88\xc5\x89\x86\x03\xf77\x9c2*\x1b'
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
