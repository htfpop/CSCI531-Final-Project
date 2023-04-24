import socket

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.dh import DHParameters, DHPrivateKey, DHPublicKey, DHParameterNumbers
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SUCCESS = 0x00000000
FAILURE = 0xFFFFFFFF


class Server:
    def __init__(self, params=None, priv=None, public=None, shared=None, derived=None):
        self.params: DHParameters = params
        self.priv: DHPrivateKey = priv
        self.public: DHPublicKey = public
        self.shared: bytes = shared
        self.derived = derived

    def get_params(self): return self.get_params

    def get_priv(self): return self.priv

    def get_shared(self): return self.public


class Public_Packet:
    def __init__(self, params=None, shared=None, message=None):
        self.params: DHParameters = params
        self.shared = shared
        self.message = message

    def get_params(self): return self.get_params

    def get_shared(self): return self.shared


"""
Function    : main()
Description : main function used for accepting client requests to connect
Parameters  : None
Outputs     : None
"""


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


"""
Function    : serv_pre_connect()
Description : Perform simple handshake to ensure stability of connection to client
Parameters  : server_socket - socket object used for transmission and reception
Outputs     : client_socket - instance of client currently connected
"""


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


"""
Function    : crypto_service()
Description : generate DH parameters (g, p, pk_serv)
Parameters  : None
Outputs     : Server - Server object
"""


def crypto_service():
    params = dh.generate_parameters(generator=2, key_size=1024)
    priv_key = params.generate_private_key()
    pub_key = params.generate_private_key().public_key()

    return Server(params, priv_key, pub_key)


"""
Function    : serv_post_connect()
Description : Transmit prime (p), generator (g), and server's public key (pk_serv),
              receive client's public key, and computer shared secret
Parameters  : Server - server object
              client - currently connected client
Outputs     : None
"""


def serv_post_connect(serv: Server, client: socket):
    print(f'[DEBUG]: Generating Shared Secret')
    print(f'[DEBUG]: Sending parameters')
    temp1 = serv.params.parameter_numbers()
    pk_server = serv.priv.public_key().public_numbers().y.to_bytes(length=128, byteorder='big')
    p = temp1.p.to_bytes(length=128, byteorder='big')
    g = temp1.g.to_bytes(length=1, byteorder='big')

    print(f'[DEBUG]: Sending prime (p) to client')
    client.sendall(p)
    # print(f'[DEBUG]: Sent: {p} to client')
    print(f'[DEBUG]: Sent: prime (p) to client')
    print(' '.join('{:02x}'.format(x) for x in p))

    print(f'[DEBUG]: Sending generator (g) to client')
    client.sendall(g)
    # print(f'[DEBUG]: Sent: {g} to client')
    print(f'[DEBUG]: Sent: generator (g) to client')
    print(' '.join('{:02x}'.format(x) for x in g))

    print(f'[DEBUG]: sending public key (pk_server) to client')
    client.sendall(pk_server)
    # print(f'[DEBUG]: Sent: {pk_server} to client')
    print(f'[DEBUG]: Sent: server public key (pk_server) to client')
    print(' '.join('{:02x}'.format(x) for x in pk_server))

    print(f'[DEBUG]: Receiving pk (pk_client) from client')
    c_pk = client.recv(1024)
    # print(f'[DEBUG]: Sent: {pk_server} to client')
    print(' '.join('{:02x}'.format(x) for x in c_pk))

    y_int = int.from_bytes(c_pk, byteorder="big")

    nums: DHParameterNumbers = dh.DHParameterNumbers(serv.params.parameter_numbers().p,
                                                     serv.params.parameter_numbers().g)
    params = nums.parameters()
    peer_pub = dh.DHPublicNumbers(y_int, nums)

    print(f'[DEBUG]: SHARED SECRET')
    shared = serv.priv.exchange(peer_pub.public_key())
    print(' '.join('{:02x}'.format(x) for x in shared))

    # CKL 4/24 update - derive 128 bit key from shared secret for AES processing
    kdf = HKDF(algorithm=SHA256(),
               length=16,
               salt=None,
               info=b'128key')
    derived_key = kdf.derive(shared)

    #DO NOT USE IN PRODUCTION!!!
    print(f'[DEBUG]: HKDF DERIVED AES128 RED KEY')
    print(' '.join('{:02x}'.format(x) for x in derived_key))

    serv.shared = shared
    serv.derived = derived_key


"""
Function    : 
Description : After performing DH key exchange, check 128 byte data with server
              Client will send over shared secret first
Parameters  : serv - 
              client - 
Outputs     : 
"""
def check_shared(serv: Server, client: socket):
    """
    check_shared()
    :param serv: server object used for storage of shared secret, and private keys
    :param client: socket object used for sending and receiving data
    :return: None
    """
    print(f'[DEBUG]: Check shared secret')
    client_shared = client.recv(1024)

    mismatch_flag = False
    if client_shared != serv.shared:
        mismatch_flag = True

    if mismatch_flag:
        print(f'[DEBUG]: SHARED SECRET MISMATCH')
        client.close()
        return FAILURE
    else:
        print(f'[DEBUG]: GOOD SHARED SECRET')
        print(f'[DEBUG]: Sending shared to client')
        client.sendall(serv.shared)
        return SUCCESS


def check_derived(serv: Server, client: socket):
    """
    check_derived()
    :param serv: server object used for storage of shared secret, and private keys
    :param client: socket object used for sending and receiving data
    :return: None
    """
    print(f'[DEBUG]: Check HKDF derived key')
    client_derived = client.recv(1024)

    mismatch_flag = False
    if client_derived != serv.derived:
        mismatch_flag = True

    if mismatch_flag:
        print(f'[DEBUG]: DERIVED KEY MISMATCH')
        client.close()
        return FAILURE
    else:
        print(f'[DEBUG]: GOOD DERIVED KEY')
        print(f'[DEBUG]: Sending derived key to client')
        client.sendall(serv.derived)
        return SUCCESS


"""
Function    : test_server()
Description : Test socket connection, handshake, and DH key exchange
Parameters  : None
Outputs     : None
"""
def test_server():
    print("---Server---")
    status = FAILURE

    # generate Diffie-Hellman parameters/private/public keys
    serv = crypto_service()

    # create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # attempt to accept client
    client: socket = serv_pre_connect(server_socket)

    # DH key exchange
    serv_post_connect(serv, client)

    # check shared secret - DO NOT USE IN PRODUCTION
    status = check_shared(serv, client)

    # check derived shared AES 128 RED key - DO NOT USE IN PRODUCTION
    if status == SUCCESS:
        status = check_derived(serv, client)

    # Decrypt simple message with AES128 that was received from client
    if status == SUCCESS:
        status = receive_msg(serv, client)

    print(f'[Server]: Closing connection')
    server_socket.close()


def receive_msg(serv: Server, client: socket):
    """
    Receives 1 encrypted message from Client.py - using HKDF derived key from
    DH shared secret
    :param serv: instance of our server object
    :param client: socket that receives incoming communication from client.py
    :return: SUCCESS if decrypted message matches KNOWNANSWER // FAILURE otherwise
    """
    status = FAILURE
    unpadder = padding.PKCS7(128).unpadder()
    key = serv.derived
    KNOWNANSWER = b"Read EHR"
    print(f'[Server]: Receiving encrypted message')

    ct = client.recv(1024)

    try:
        cipher = Cipher(algorithms.AES128(key), modes.ECB())
    except ValueError:
        print(f'[VALUE ERROR]: Invalid AES-128 Key. Have you used the right key?\nExiting.')
        exit(-1)

    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()

    unpadderdata = unpadder.update(pt)
    unpadderdata += unpadder.finalize()

    print(f'[Server]: Plaintext - {unpadderdata}')

    # Test for decrypted message from client
    if unpadderdata == KNOWNANSWER:
        status = SUCCESS

    return status


if __name__ == "__main__":
    test_server()
#   main()
