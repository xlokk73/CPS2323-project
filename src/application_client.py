#!/usr/bin/python3           # This is application_client.py file
import json
from socket import create_connection
from ssl import SSLContext, PROTOCOL_TLS_CLIENT

hostname = 'example.org'
ip = '127.0.0.1'
port = 8443
context = SSLContext(PROTOCOL_TLS_CLIENT)
context.load_verify_locations('cert.pem')

client = create_connection((ip, port))
tls = context.wrap_socket(client, server_hostname=hostname)
print(f'Using {tls.version()}\n')

login_dict = {
    "type": "application",
    "username": input("Enter username: "),
}

login_json = json.dumps(login_dict)

tls.sendall(login_json.encode())

data = tls.recv(1024)
print(f'Server says: {data.decode()}')

while 1:
    function_dict = False

    print("1) encrypt")
    print("2) decrypt")
    print("3) sign")
    print("4) verify")

    option = input("Enter option number: ")
    
    if option == "1":
        print("Encrypting")

        function_dict = {
            "function" : "encrypt",
            "key_name" : input("Enter key name:"), 
            "plaintext" : input("Enter plaintext:"),
        }

    elif option == "2":
        print("Decrypting")

        function_dict = {
            "function" : "decrypt",
            "key_name" : input("Enter key name:"), 
            "key_version" : input("Enter key version:"), 
            "cipher_text" : input("Enter cipher text:"),
        }

        
    elif option == "3":
        print("Signing")

        function_dict = {
            "function" : "sign",
            "key_name" : input("Enter key name:"), 
            "message" : input("Enter message:"),
        }

    elif option == "4":
        print("Verifying")

        function_dict = {
            "function" : "verify",
            "key_name" : input("Enter key name:"), 
            "key_version" : input("Enter key version:"), 
            "message" : input("Enter message:"),
            "digest" : input("Enter digest:"),
        }

    else:
        print("Invalid input bro")

    if function_dict:
        function_json = json.dumps(function_dict)
        tls.sendall(function_json.encode())

        data = tls.recv(1024)
        print(f'Server says: {data}')
