from socket import socket, AF_INET, SOCK_STREAM
from ssl import SSLContext, PROTOCOL_TLS_SERVER


ip = '127.0.0.1'
port = 8443
context = SSLContext(PROTOCOL_TLS_SERVER)
context.load_cert_chain('cert.pem', 'key.pem')


server = socket(AF_INET, SOCK_STREAM)
server.bind((ip, port))
server.listen(1)
tls = context.wrap_socket(server, server_side=True)
connection, address = tls.accept()
print(f'Connected by {address}\n')

data = connection.recv(1024)
print(f'Client Says: {data}')

connection.sendall(b"You're welcome")

data = connection.recv(1024)
print(f'Client Says: {data}')