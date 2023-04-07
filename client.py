import socket
import stdiomask
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.dh import DHParameters, DHPrivateKey, DHPublicKey, DHParameterNumbers
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key


class Client:
    def __init__(self, params=None, priv=None, public=None, shared=None):
        self.params: DHParameters = params
        self.priv: DHPrivateKey = priv
        self.public: DHPublicKey = public
        self.shared: bytes = shared

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
    # print(f'[DEBUG]: Received prime {p} from server')
    print(' '.join('{:02x}'.format(x) for x in p))

    print(f'[DEBUG]: Receiving generator (g) from server')
    g = client_socket.recv(2)
    # print(f'[DEBUG]: Received generator {g} from server')
    print(' '.join('{:02x}'.format(x) for x in g))

    print(f'[DEBUG]: Receiving public key (pk_client) from server')
    pk_client = client_socket.recv(1024)
    # print(f'[DEBUG]: Received generator {pk_client} from server')
    print(' '.join('{:02x}'.format(x) for x in pk_client))

    p_int = int.from_bytes(p, byteorder="big")
    g_int = int.from_bytes(g, byteorder="big")
    y_int = int.from_bytes(pk_client, byteorder="big")

    nums: DHParameterNumbers = dh.DHParameterNumbers(p_int, g_int)
    params = nums.parameters()
    c_priv = params.generate_private_key()
    c_pub = params.generate_private_key().public_key()
    peer_pub = dh.DHPublicNumbers(y_int, nums)

    # generate public and private keys
    client = Client(params, c_priv, c_pub)

    print(f'[DEBUG]: Sending public key (pk_client) to server')
    pk_client = client.priv.public_key().public_numbers().y.to_bytes(length=128, byteorder='big')
    client_socket.sendall(pk_client)
    # print(f'[DEBUG]: Received generator {pk_client} from server')
    print(' '.join('{:02x}'.format(x) for x in pk_client))

    print(f'[DEBUG]: SHARED SECRET')
    shared = c_priv.exchange(peer_pub.public_key())
    print(' '.join('{:02x}'.format(x) for x in shared))

    client.shared = shared

    return client


def gen_key():
    c_params = dh.generate_parameters(generator=2, key_size=1024)
    c_priv_key = c_params.generate_private_key()
    c_pub_key = c_params.generate_private_key().public_key()

    return Client(c_params, c_priv_key, c_pub_key)


def check_shared(client: Client, client_socket: socket):
    print(f'[DEBUG]: Check shared secret')
    client_socket.sendall(client.shared)

    print(f'[DEBUG]: Receiving shared from server')
    server_shared = client_socket.recv(1024)

    mismatch_flag = False
    if server_shared != client.shared:
        mismatch_flag = True

    if mismatch_flag:
        print(f'[DEBUG]: SHARED SECRET MISMATCH')
        client_socket.close()
    else:
        print("GOOD SHARED SECRET")


def test_client():
    print("---Client---")

    # create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # establish stable connection handshake
    client_pre_connect(client_socket)

    # perform DH Key Exchange
    client = client_post_connect(client_socket)

    check_shared(client, client_socket)

    print(f'[Client]: Closing connection')
    client_socket.close()


if __name__ == "__main__":
    test_client()
#    main()
