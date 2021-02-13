#!/usr/bin/python3           # This is server.py file
from socket import socket, AF_INET, SOCK_STREAM
from ssl import SSLContext, PROTOCOL_TLS_SERVER
from Crypto.Protocol.KDF import PBKDF2
from keys import *
import threading
import json


class MasterKey:
    part_1 = False
    part_2 = False


def handle_admin(connec, addr, login_dict):
    connec.sendall(b'Handling admin')

    while 1:
        data = connec.recv(1024)
        print(f'Client {addr} Says: {data}')

        if data == b'CHANGE_MASTER_KEY':
            print('changing master key')
            connec.sendall(b'changing master key')

        elif data == b'ROTATE_KEY_ENCRYPTION_KEY':
            print('rotating key encryption key')
            connec.sendall(b'rotating key encryption key')

        elif data == b'GET_APPLICATION_KEYS_INFO':
            print('getting application keys info')
            connec.sendall(b'getting application keys info')

        elif data == b'GET_APPLICATION_KEY_INFO':
            print('getting app info')
            connec.sendall(b'getting app info')

        elif data == b'CREATE_ APPLICATION_KEY':
            print('creating application key')
            connec.sendall(b'creating application key')

        elif data == b'UPDATE_APPLICATION_KEY':
            print('updating application key')
            connec.sendall(b'updating application key')

        elif data == b'UPDATE_APPLICATION_KEY_STATE':
            print('update application key state')
            connec.sendall(b'update application key state')

        else:
            print('Command does not exist')
            connec.sendall(b'totally not OK')




def handle_application(connection, address):
    print("Handling Application")
    connection.sendal(b'OK')


def on_new_client(connection, address):
    login_json = connection.recv(1024)
    login_dict = json.loads(login_json.decode())

    # if admin
    if login_dict["type"] == "admin":
        print(f'Client {addr} Says: {login_dict}')
        data = "Hello, Welcome " + login_dict["username"]

        if not MasterKey.part_1:
            MasterKey.part_1 = gen_master_key_part(login_dict["username"], login_dict["password"])
            MasterKey.is_waiting = True

            print("Waiting for other admin")
            while MasterKey.is_waiting:
                pass

            handle_admin(connection, address, login_dict)

        elif MasterKey.is_waiting:
            MasterKey.part_2 = gen_master_key_part(login_dict["username"], login_dict["password"])
            if verify_master_key(gen_master_key(MasterKey.part_1, MasterKey.part_2), KEK):
                MasterKey.is_waiting = False
                handle_admin(connection, address, login_dict)

            exit()

    # if application
    else:
        handle_application(connection, address)

application_keys = [gen_application_key(), gen_application_key()]

output_file = 'file_vault.bin'  # Output file
open(output_file, 'w').close()  # Clear file contents
# KEK = get_key_encryption_key()  # Must be a bytes object

MK_part_1 = gen_master_key_part("manwel", "password1")
MK_part_2 = gen_master_key_part("christian", "password2")

MK_1 = gen_master_key_1(gen_master_key(MK_part_1, MK_part_2))

KEK = gen_key_encryption_key(MK_1)

# Encrypt and store the Key Encryption Key
encrypt_and_store(MK_1, KEK, output_file)

MK_2 = gen_master_key_2(gen_master_key(MK_part_1, MK_part_2))

# MAC and store the Key Encryption Key
mac_and_store(MK_2, KEK, output_file)

KEK_1 = PBKDF2(KEK, b"kek 1", dkLen=16)

# Encrypt and store Application Keys
for application_key in application_keys:
    encrypt_and_store(KEK_1, application_key, output_file)

KEK_2 = PBKDF2(KEK, b"kek 2", dkLen=16)

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
