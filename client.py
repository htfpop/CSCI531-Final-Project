import socket
import stdiomask
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.dh import DHParameters, DHPrivateKey, DHPublicKey, DHParameterNumbers
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class Client:
    def __init__(self, params=None, priv=None, shared=None):
        self.params = params
        self.priv = priv
        self.shared = shared

    def get_params(self): return self.get_params

    def get_priv(self): return self.priv

    def get_shared(self): return self.shared


def main():
    print("---Client---")
    email = input("[Client]: Enter Email: ")
    password = stdiomask.getpass(prompt="[Client]: Password:", mask="*")
    print(f'[DEBUG]: {email}:{password}')
    client_handler(email, password)


def client_handler(email, password):
    # create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connect the socket to the server's IP address and port
    server_address = ('localhost', 8888)
    client_socket.connect(server_address)

    # send the message to the server
    message = email + ',' + password
    client_socket.sendall(message.encode())

    # receive the response from the server
    response = client_socket.recv(1024)
    print(f'[Client.py]: {response.decode()}')

    # close the socket
    client_socket.close()


def client_pre_connect(client_socket):
    # connect the socket to the server's IP address and port
    server_address = ('localhost', 8888)
    client_socket.connect(server_address)

    # send the message to the server
    message = "Hello, Server!"
    client_socket.sendall(message.encode())

    # receive the response from the server
    response = client_socket.recv(1024).decode()
    print(f'[Client.py]: Received message: {response}')

    if response != "Hello, Client!":
        print(f'[DEBUG]: ERROR - Did not receive correct connect handshake from server')
        client_socket.close()
    else:
        print(f'[DEBUG]: Valid handshake received!')


def client_post_connect(client_socket: socket):
    print(f'[DEBUG]: --- Generating Shared Secret ---')

    print(f'[DEBUG]: Receiving prime (p) from server')
    p = client_socket.recv(1024)
    #print(f'[DEBUG]: Received prime {p} from server')
    print(' '.join('{:02x}'.format(x) for x in p))

    print(f'[DEBUG]: Receiving generator (g) from server')
    g = client_socket.recv(2)
    #print(f'[DEBUG]: Received generator {g} from server')
    print(' '.join('{:02x}'.format(x) for x in g))

    print(f'[DEBUG]: Receiving public key (pk_client) from server')
    pk_client = client_socket.recv(1024)
    #print(f'[DEBUG]: Received generator {pk_client} from server')
    print(' '.join('{:02x}'.format(x) for x in pk_client))

    #params: DHParameterNumbers = dh.DHParameterNumbers(p, g)
    #client_secret: DHPrivateKey = params.generate_private_key()
    #client_public: DHPublicKey = client_secret.public_key()

    # shared_secret = client_secret.exchange(pk_client)


def test_client():
    print("---Client---")

    # create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # establish stable connection handshake
    client_pre_connect(client_socket)

    # perform DH Key Exchange
    shared_secret = client_post_connect(client_socket)

    print(f'[Client]: Closing connection')
    client_socket.close()


if __name__ == "__main__":
    test_client()
#    main()
