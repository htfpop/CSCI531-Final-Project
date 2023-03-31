import socket
import pickle
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.dh import DHParameters, DHPrivateKey, DHPublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization


class Server:
    def __init__(self, params=None, priv=None, shared=None):
        self.params: DHParameters = params
        self.priv: DHPrivateKey = priv
        self.shared: DHPublicKey = shared

    def get_params(self): return self.get_params

    def get_priv(self): return self.priv

    def get_shared(self): return self.shared


class Public_Packet:
    def __init__(self, params=None, shared=None, message=None):
        self.params: DHParameters = params
        self.shared = shared
        self.message = message

    def get_params(self): return self.get_params

    def get_shared(self): return self.shared


def main():
    # create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # bind the socket to a specific IP address and port
    server_address = ('localhost', 8888)
    server_socket.bind(server_address)

    # listen for incoming connections
    server_socket.listen(1)
    print('Server is listening on', server_address)

    while True:
        # wait for a connection
        client_socket, client_address = server_socket.accept()
        print('[Server]: Received connection from', client_address)

        # receive the message from the client
        message = client_socket.recv(1024).decode()
        print('[Server]: Received message:', message)
        separate = message.split(',')

        # send the response back to the client
        response = 'Hello, ' + separate[0]
        client_socket.sendall(response.encode())
        print('[Server]: Sent response: \"{response}\"')

        # close the connection
        client_socket.close()


def serv_pre_connect(server_socket: socket):
    # bind the socket to a specific IP address and port
    server_address = ('localhost', 8888)
    server_socket.bind(server_address)

    # listen for incoming connections
    server_socket.listen(1)
    print('Server is listening on', server_address)

    # wait for a connection
    client_socket, client_address = server_socket.accept()
    print('[Server]: Received connection from', client_address)

    # receive the message from the client
    message = client_socket.recv(1024).decode()
    print('[Server]: Received message:', message)

    if message != "Hello, Server!":
        print(f'[DEBUG]: ERROR - Did not receive correct connect handshake from client')
        client_socket.close()
        server_socket.close()
    else:
        # send the response back to the client
        print(f'[DEBUG]: Valid handshake received!')
        response = 'Hello, Client!'
        client_socket.sendall(response.encode())
        print(f'[Server]: Sent response: \"{response}\"')

    return client_socket


def crypto_service():
    params = dh.generate_parameters(generator=2, key_size=1024)
    priv_key = params.generate_private_key()
    shared_secret = params.generate_private_key().public_key()

    return Server(params, priv_key, shared_secret)


def serv_post_connect(serv: Server, client: socket):
    print(f'[DEBUG]: Generating Shared Secret')
    print(f'[DEBUG]: Sending parameters')
    temp1 = serv.params.parameter_numbers()
    pk_server = serv.priv.public_key().public_numbers().y.to_bytes(length=128, byteorder='big')
    p = temp1.p.to_bytes(length=128, byteorder='big')
    g = temp1.g.to_bytes(length=1, byteorder='big')

    print(f'[DEBUG]: Sending prime (p) to client')
    client.sendall(p)
    #print(f'[DEBUG]: Sent: {p} to client')
    print(f'[DEBUG]: Sent: prime (p) to client')
    print(' '.join('{:02x}'.format(x) for x in p))

    print(f'[DEBUG]: Sending generator (q) to client')
    client.sendall(g)
    #print(f'[DEBUG]: Sent: {g} to client')
    print(f'[DEBUG]: Sent: generator (g) to client')
    print(' '.join('{:02x}'.format(x) for x in g))

    print(f'[DEBUG]: public key (pk_server) to client')
    client.sendall(pk_server)
    #print(f'[DEBUG]: Sent: {pk_server} to client')
    print(f'[DEBUG]: Sent: server public key (pk_server) to client')
    print(' '.join('{:02x}'.format(x) for x in pk_server))


def test_server():
    print("---Server---")

    # generate Diffie-Hellman parameters/private/public keys
    serv = crypto_service()

    # create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # attempt to accept client
    client: socket = serv_pre_connect(server_socket)

    # DH key exchange
    serv_post_connect(serv, client)

    print(f'[Server]: Closing connection')
    server_socket.close()


def dhell():
    params = dh.generate_parameters(generator=2, key_size=1024)
    priv1 = params.generate_private_key()
    pub1 = priv1.public_key()

    temp1 = params.parameter_numbers()
    temp2 = temp1.p
    temp3 = temp1.g


if __name__ == "__main__":
    #    dhell()
    test_server()
#    main()
