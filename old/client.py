import socket
import stdiomask
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.dh import DHParameters, DHPrivateKey, DHPublicKey, DHParameterNumbers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SUCCESS = 0x00000000
FAILURE = 0xFFFFFFFF


class Client:
    def __init__(self, params=None, priv=None, public=None, shared=None, derived=None):
        self.params: DHParameters = params
        self.priv: DHPrivateKey = priv
        self.public: DHPublicKey = public
        self.shared: bytes = shared
        self.derived = derived

    def get_params(self): return self.get_params

    def get_priv(self): return self.priv

    def get_shared(self): return self.shared


"""
Function    : client_handler()
Description : Loopback Test to ensure server received client's email and password
Parameters  : email - email string
              password - password string
Outputs     : None
"""


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


"""
Function    : client_pre_connect()
Description : Perform simple handshake to ensure stability of connection to server
Parameters  : client_socket - socket object used for transmission and reception
Outputs     : None
"""


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


"""
Function    : client_post_connect()
Description : Receive prime (p), generator (g), and server's public key (pk_serv)
              Compute shared secret
Parameters  : client_socket - socket object used for transmission and reception
Outputs     : None
"""


def client_post_connect(client_socket: socket):
    print(f'[DEBUG]: --- Generating Shared Secret ---')

    print(f'[DEBUG]: Receiving prime (p) from server')
    p = client_socket.recv(1024)
    print(' '.join('{:02x}'.format(x) for x in p))

    print(f'[DEBUG]: Receiving generator (g) from server')
    g = client_socket.recv(1)
    print(' '.join('{:02x}'.format(x) for x in g))

    print(f'[DEBUG]: Receiving public key (pk_client) from server')
    pk_client = client_socket.recv(1024)
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

    kdf = HKDF(algorithm=SHA256(),
               length=16,
               salt=None,
               info=b'128key')
    derived_key = kdf.derive(shared)

    # DO NOT USE IN PRODUCTION!!!
    print(f'[DEBUG]: HKDF DERIVED AES128 RED KEY')
    print(' '.join('{:02x}'.format(x) for x in derived_key))

    client.shared = shared
    client.derived = derived_key

    return client


"""
Function    : check_shared()
Description : After performing DH key exchange, check 128 byte data with server
              Client will send over shared secret first
Parameters  : client - client object used for storage of shared secret, and private keys
              client_socket - socket object used for sending and receiving data
Outputs     : None
"""


def check_shared(client: Client, client_socket: socket):
    print(f'[DEBUG]: Check shared secret')
    client_socket.sendall(client.shared)
    mismatch_flag = False

    print(f'[DEBUG]: Receiving shared from server')
    server_shared = client_socket.recv(1024)

    if server_shared != client.shared:
        mismatch_flag = True

    if mismatch_flag:
        print(f'[DEBUG]: SHARED SECRET MISMATCH')
        client_socket.close()
        return FAILURE
    else:
        print("GOOD SHARED SECRET")
        return SUCCESS


def check_derived(client: Client, client_socket: socket):
    """
    Checking derived - DO NOT USE IN PRODUCTION (AES RED KEY)
    :param client:        client object
    :param client_socket: socket for sending data
    :return: FAILURE if mismatch // SUCCESS otherwise
    """
    print(f'[DEBUG]: Checking HKDF derived key')
    client_socket.sendall(client.derived)
    mismatch_flag = False

    print(f'[DEBUG]: Receiving HKDF derived key from server')
    server_derived = client_socket.recv(1024)

    if server_derived != client.derived:
        mismatch_flag = True

    if mismatch_flag:
        print(f'[DEBUG]: DERIVED KEY MISMATCH')
        client_socket.close()
        return FAILURE
    else:
        print("GOOD DERIVED KEY")
        return SUCCESS


"""
Function    : test_client()
Description : Test socket connection, handshake, and DH key exchange
Parameters  : None
Outputs     : None
"""


def test_client():
    print("---Client---")
    status = FAILURE

    # create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # establish stable connection handshake
    client_pre_connect(client_socket)

    # perform DH Key Exchange
    client = client_post_connect(client_socket)

    # check shared secret - DO NOT USE IN PRODUCTION
    status = check_shared(client, client_socket)

    # check derived shared AES 128 RED key - DO NOT USE IN PRODUCTION
    if status == SUCCESS:
        status = check_derived(client, client_socket)

    # Encrypt simple message with AES128 and transmit to server
    if status == SUCCESS:
        status = transmit_msg(client, client_socket)

    print(f'[Client]: Closing connection')
    client_socket.close()


def transmit_msg(client: Client, serv: socket):
    """
    Transmits 1 encrypted message to server.py - using HKDF derived key from
    DH shared secret
    :param client: instance of our client object
    :param serv: socket that transmits messages to server.py
    :return: SUCCESS if decrypted message matches KNOWNANSWER // FAILURE otherwise
    """
    padder = padding.PKCS7(128).padder()
    status = FAILURE
    test_msg = b"Read EHR"
    print(f'[Client]: Transmitting encrypted message')

    key = client.derived
    print(f'keysize:{len(key)}')

    print(' '.join('{:02x}'.format(x) for x in key))

    try:
        cipher = Cipher(algorithms.AES128(key), modes.ECB())
    except ValueError:
        print(f'[VALUE ERROR]: Invalid AES-128 Key. Have you used the right key?\nExiting.')
        exit(-1)

    encryptor = cipher.encryptor()

    padder_data = padder.update(test_msg)
    padder_data += padder.finalize()

    ct = encryptor.update(padder_data) + encryptor.finalize()

    serv.sendall(ct)

    # TEST PADDER AND DEPADDER
    print(f'[Client]: Cipher text - {ct}')

    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()

    print(f'[Client]: Plaintext - {pt}')

    if pt == ct:
        status = SUCCESS
    else:
        status = FAILURE

    return status


"""
Function    : main()
Description : Main entry point -- currently not used due to testing
Parameters  : None
Outputs     : None
"""


def main():
    print("---Client---")
    email = input("[Client]: Enter Email: ")
    password = stdiomask.getpass(prompt="[Client]: Password:", mask="*")
    print(f'[DEBUG]: {email}:{password}')
    client_handler(email, password)


def AES128Test():
    """
    Test for AES128 with hardcoded key usage of Padding/Unpadding
    :return: SUCCESS - PT == original test message // FAILURE otherwise
    """
    # Block size should be 128 bytes
    padder = padding.PKCS7(128).padder()
    test_msg = b"Read EHR"

    # obtain input all plaintext data and use red-key to encrypt
    key = [0x9b, 0x9c, 0xaa, 0x1f, 0x1d, 0x1c, 0x4b, 0x08, 0xdb, 0x29, 0xe3, 0xf3, 0x69, 0x09, 0x7e, 0x62]
    key = bytes(key)
    print(' '.join('{:02x}'.format(x) for x in key))
    print(f'key size:{len(key)}')

    try:
        cipher = Cipher(algorithms.AES128(key), modes.ECB())
    except ValueError:
        print(f'[VALUE ERROR]: Invalid AES-128 Key. Have you used the right key?\nExiting.')
        exit(-1)

    encryptor = cipher.encryptor()

    padder_data = padder.update(test_msg)
    padder_data += padder.finalize()

    ct = encryptor.update(padder_data) + encryptor.finalize()

    print(f'[Client]: Transmitting encrypted message')

    print(f'[Client]: Cipher text - {ct}')

    # get AES red key used for decrypting ciphertext
    unpadder = padding.PKCS7(128).unpadder()

    try:
        cipher = Cipher(algorithms.AES128(key), modes.ECB())
    except ValueError:
        print(f'[VALUE ERROR]: Invalid AES-128 Key. Have you used the right key?\nExiting.')
        exit(-1)

    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()

    unpadderdata = unpadder.update(pt)
    unpadderdata += unpadder.finalize()

    print(f'[Client]: Plaintext - {unpadderdata}')

    if pt == ct:
        status = SUCCESS
    else:
        status = FAILURE

    return status


if __name__ == "__main__":
    test_client()
#   AES128Test()
#   main()
