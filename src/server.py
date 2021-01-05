#!/usr/bin/python3           # This is server.py file    

from socket import socket, AF_INET, SOCK_STREAM
from ssl import SSLContext, PROTOCOL_TLS_SERVER
from Crypto.Protocol.KDF import PBKDF2
from keys import *
import threading
import json


def handle_admin(connec, addr, login_dict):
    print(f'Client {addr} Says: {login_dict}')
    data = "Hello, Welcome " + login_dict["username"]

    mkp1 = gen_master_key_part(login_dict["username"], login_dict["password"])
    print("Master Key part 1:", mkp1)

    connec.sendall(data.encode())

    while 1:
        data = connec.recv(1024)
        print(f'Client {addr} Says: {data}')

        connec.sendall(b'OK')


def handle_application(connection, address):
    print("Handling Application")
    connection.sendal(b'OK')


def on_new_client(connection, address):
    login_json = connection.recv(1024)
    login_dict = json.loads(login_json.decode())

    if login_dict["type"] == "admin":
        handle_admin(connection, address, login_dict)

    else:
        handle_application(connection, address)


application_keys = [gen_application_key(), gen_application_key()]

output_file = 'file_vault.bin'  # Output file
open(output_file, 'w').close()  # Clear file contents
KEK = get_key_encryption_key()  # Must be a bytes object

MK_part_1 = get_master_key_part_1()
MK_part_2 = get_master_key_part_2()

MK_1_pass = "master key 1"
MK_1 = PBKDF2(MK_1_pass, gen_master_key(MK_part_1, MK_part_2), dkLen=16)

# Encrypt and store the Key Encryption Key
encrypt_and_store(MK_1, KEK, output_file)

MK_2_pass = "master key 2"
MK_2 = PBKDF2(MK_2_pass, gen_master_key(MK_part_1, MK_part_2), dkLen=16)

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

# Communication with the client

ip = '127.0.0.1'
port = 8443
context = SSLContext(PROTOCOL_TLS_SERVER)
context.load_cert_chain('cert.pem', 'key.pem')

server = socket(AF_INET, SOCK_STREAM)
server.bind((ip, port))
server.listen(1)
tls = context.wrap_socket(server, server_side=True)

while 1:
    c, addr = tls.accept()
    print(f'Connected by {addr}\n')

    thread = threading.Thread(target=on_new_client, args=(c, addr))
    thread.start()
