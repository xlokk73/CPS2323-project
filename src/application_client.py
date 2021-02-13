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
    msg = input("Enter your message: ")
    tls.sendall(msg.encode())

    data = tls.recv(1024)
    print(f'Server says: {data}')
