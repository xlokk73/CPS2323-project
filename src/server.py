#!/usr/bin/python3           # This is server.py file    

from socket import socket, AF_INET, SOCK_STREAM
from ssl import SSLContext, PROTOCOL_TLS_SERVER
from Crypto.Protocol.KDF import PBKDF2
from keys import *
import threading

def on_new_client(connection, address):

    data = connection.recv(1024)
    print(f'Client {address} Says: {data}')
    
    connection.sendall(b"Hello, Welcome")
    
    while(1):
        data = connection.recv(1024)
        print(f'Client {address} Says: {data}')
    
        connection.sendall(b'OK')
    connection.close()


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

# Communication with the client

ip = '127.0.0.1'
port = 8443
context = SSLContext(PROTOCOL_TLS_SERVER)
context.load_cert_chain('cert.pem', 'key.pem')


server = socket(AF_INET, SOCK_STREAM)
server.bind((ip, port))
server.listen(1)
tls = context.wrap_socket(server, server_side=True)

while (1):
    connection, address = tls.accept()
    print(f'Connected by {address}\n')

    thread = threading.Thread(target=on_new_client,args=(connection,address))
    thread.start()
    
tls.close()
