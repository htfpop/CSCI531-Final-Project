import base64
import hashlib
from datetime import time

from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.dh import DHParameters, DHPrivateKey, DHPublicKey, DHParameterNumbers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from p2pnetwork.node import Node
import json
import sys

import AuditNotifier

# globals
RESPONSE_TIMEOUT = 20
HOST_NODE = 0xCAFECAFE
VISITOR_NODE = 0xC0FFEE01
FAILURE = 0xDEADBEEF


class FileSharingNode(Node):

    def __init__(self, host, port, id=None, callback=None, params=None,
                 priv=None, public=None, shared=None, derived=None, max_connections=0):
        super(FileSharingNode, self).__init__(host, port, id, callback, max_connections)
        self.params: DHParameters = params
        self.priv: DHPrivateKey = priv
        self.public: DHPublicKey = public
        self.shared: bytes = shared
        self.derived = derived
        self.connected = False
        self.peer = "None"
        self.state = VISITOR_NODE

    def outbound_node_connected(self, connected_node):
        print("outbound_node_connected: " + connected_node.id)
        self.connected = True
        self.peer = connected_node.id

    def inbound_node_connected(self, connected_node):
        print("inbound_node_connected: " + connected_node.id)
        self.connected = True
        self.peer = connected_node.id
        self.state = HOST_NODE  # Visitor now becomes key host
        self.DH_Check()
        self.DH_Handshake()

    def inbound_node_disconnected(self, connected_node):
        print("inbound_node_disconnected: " + connected_node.id)
        self.connected = False
        self.peer = "None"

    def outbound_node_disconnected(self, connected_node):
        print("outbound_node_disconnected: " + connected_node.id)
        self.connected = False
        self.peer = "None"

    def get_stats(self):
        print(f'{self.id} Instance Object:\n'
              f'-----------------------\n'
              f'Connected: {self.connected}\n'
              f'Connected Peer: {self.peer}\n'
              f'Private Key: {self.priv}\n'
              f'Public Key: {self.public}\n'
              f'Shared Key: {self.shared}\n'
              )

    def DH_Check(self):
        # if shared secret is already established
        if self.shared is None and self.public is None and self.priv is None:
            print(f'Shared Secret already established')
            return

        # first time setup
        self.DH_Init()

    def DH_Init(self):
        params = dh.generate_parameters(generator=2, key_size=1024)
        self.params = params
        self.priv = params.generate_private_key()
        self.public = params.generate_private_key().public_key()
        print(f'[DEBUG]: Generated DH Private/Public Key pairs')

    def DH_Handshake(self):
        # sanity check
        if self.shared is None and self.public is None and self.priv is None:
            self.DH_Init()

        temp1 = self.params.parameter_numbers()
        pk_server = self.priv.public_key().public_numbers().y.to_bytes(length=128, byteorder='big')
        p = temp1.p.to_bytes(length=128, byteorder='big')
        g = temp1.g.to_bytes(length=1, byteorder='big')

        print(f'[DEBUG]: Sending prime (p) to client')
        # send p
        # print(f'[DEBUG]: Sent: prime (p) to client')

        print(f'[DEBUG]: Sending generator (g) to client')
        # send g
        # print(f'[DEBUG]: Sent: generator (g) to client')

        print(f'[DEBUG]: sending public key (pk_server) to client')
        # send PK
        resp_data = {
            'action': "SEND_PARAMS",
            'p': base64.b64encode(p).decode('utf-8'),
            'g': base64.b64encode(g).decode('utf-8'),
            'pk_server': base64.b64encode(pk_server).decode('utf-8')
        }

        self.send_to_nodes(json.dumps(resp_data, indent=2))

        # print(f'[DEBUG]: Sent: server public key (pk_server) to client')

        # print(f'[DEBUG]: Receiving pk (pk_client) from client')
        # receive client PK
        # print(f'[DEBUG]: Received pk (pk_client) from client')

    def parse_DH_params(self, data):
        p = base64.b64decode(data['p'])
        g = base64.b64decode(data['g'])
        pk_server = base64.b64decode(data['pk_server'])

        p_int = int.from_bytes(p, byteorder="big")
        g_int = int.from_bytes(g, byteorder="big")
        y_int = int.from_bytes(pk_server, byteorder="big")

        nums: DHParameterNumbers = dh.DHParameterNumbers(p_int, g_int)
        params = nums.parameters()
        c_priv = params.generate_private_key()
        c_pub = params.generate_private_key().public_key()
        peer_pub = dh.DHPublicNumbers(y_int, nums)

        self.priv = c_priv
        self.public = c_pub
        self.public = peer_pub

        pk_visitor = self.priv.public_key().public_numbers().y.to_bytes(length=128, byteorder='big')

        shared = c_priv.exchange(peer_pub.public_key())
        print(f'[DEBUG]: SHARED SECRET')
        print(' '.join('{:02x}'.format(x) for x in shared))

        resp_data = {
            'action': "SEND_PUB",
            'pk_visitor': base64.b64encode(pk_visitor).decode('utf-8')
        }

        # CKL 4/24 update - derive 128 bit key from shared secret for AES processing
        kdf = HKDF(algorithm=SHA256(),
                   length=16,
                   salt=None,
                   info=b'128key')
        derived_key = kdf.derive(shared)

        # DO NOT USE IN PRODUCTION!!!
        print(f'[DEBUG]: HKDF DERIVED AES128 RED KEY')
        print(' '.join('{:02x}'.format(x) for x in derived_key))

        # Set shared AES Key
        self.derived = derived_key

        # Allow this node to share keys to other clients
        self.state = HOST_NODE

        self.send_to_nodes(json.dumps(resp_data, indent=2))

    def parse_visitor_pk(self, data):
        visitor_pk = base64.b64decode(data['pk_visitor'])

        y_int = int.from_bytes(visitor_pk, byteorder="big")

        nums: DHParameterNumbers = dh.DHParameterNumbers(self.params.parameter_numbers().p,
                                                         self.params.parameter_numbers().g)

        params = nums.parameters()
        peer_pub = dh.DHPublicNumbers(y_int, nums)

        print(f'[DEBUG]: SHARED SECRET')
        shared = self.priv.exchange(peer_pub.public_key())
        print(' '.join('{:02x}'.format(x) for x in shared))

        # CKL 4/24 update - derive 128 bit key from shared secret for AES processing
        kdf = HKDF(algorithm=SHA256(),
                   length=16,
                   salt=None,
                   info=b'128key')
        derived_key = kdf.derive(shared)

        # DO NOT USE IN PRODUCTION!!!
        print(f'[DEBUG]: HKDF DERIVED AES128 RED KEY')
        print(' '.join('{:02x}'.format(x) for x in derived_key))

        self.derived = derived_key

    def node_message(self, connected_node, data):
        print("Node:: node_message: Received message from node: {}".format(connected_node.id))
        print("\t(data): {} (type: {})".format(data, type(data)))

        in_dict = data

        if in_dict['action'] == 'ADD_REQUEST':
            vote = True

            resp_data = {
                'action': "RESPONSE",
                'vote': vote
            }
            resp_json = json.dumps(resp_data, indent=2)
            self.send_to_node(connected_node, resp_json)

        if in_dict['action'] == 'SEND_PARAMS':
            print("RECEIVED PARAMS\r\n")
            self.parse_DH_params(data)

        if in_dict['action'] == 'SEND_PUB':
            print("RECEIVED PK FROM VISITOR\r\n")
            self.parse_visitor_pk(data)

        if in_dict['action'] == 'SECURE_MSG_REC':
            print("RECEIVED SECURE MESSAGE\r\n")
            self.unpack_msg(data)

    def node_disconnect_with_outbound_node(self, connected_node):
        print("node wants to disconnect with other outbound node: " + connected_node.id)

    def node_request_to_stop(self):
        print("node is requested to stop!")

    def unpack_msg(self, data):
        unpadder = padding.PKCS7(128).unpadder()
        key = self.derived
        ct = data['secure_msg']
        ct = base64.b64decode(ct)

        try:
            cipher = Cipher(algorithms.AES128(key), modes.ECB())
        except ValueError:
            print(f'[VALUE ERROR]: Invalid AES-128 Key. Have you used the right key?\nExiting.')
            exit(-1)

        decryptor = cipher.decryptor()
        pt = decryptor.update(ct) + decryptor.finalize()

        unpadderdata = unpadder.update(pt)
        unpadderdata += unpadder.finalize()

        print(f'[DEBUG]: Plaintext - {unpadderdata}')


# The method prints the help commands text to the console
def print_help():
    print("Test Node App: Accepts connection and echos back approved requests.")
    print("stop - Stops the application.")
    print("connect - Connects to main node (8766).")
    print("disconnect - disconnects from main node (8766)")
    print("stats - Show node's object data")


def connect_to_node(in_node: FileSharingNode):
    host = "localhost"
    #port = 9877  # 9876 was original port
    port = 9876
    in_node.connect_with_node(host, port)


def disconnect_node(in_node: FileSharingNode):
    for c_node in in_node.all_nodes:
        in_node.disconnect_with_node(c_node)


def do_nothing(variable):
    print("Doing nothing with {}".format(variable))


def send_enc_msg(my_node: FileSharingNode, msg: str):
    padder = padding.PKCS7(128).padder()
    key = my_node.derived  # need to do check before
    pt = msg.encode('utf-8')

    try:
        cipher = Cipher(algorithms.AES128(key), modes.ECB())
    except ValueError:
        print(f'[VALUE ERROR]: Invalid AES-128 Key. Have you used the right key?\nExiting.')
        exit(-1)

    encryptor = cipher.encryptor()

    padder_data = padder.update(pt)
    padder_data += padder.finalize()

    ct = encryptor.update(padder_data) + encryptor.finalize()
    ct_64 = base64.b64encode(ct).decode('utf-8')

    data = {'action': 'SECURE_MSG_REC', 'secure_msg': ct_64}

    packed = json.dumps(data, indent=2)
    node.send_to_nodes(packed)

if __name__ == "__main__":
    peer_b = ["127.0.0.1", 9877, 'Peer_B']
    peer_c = ["127.0.0.1", 9878, 'Peer_C']

    if len(sys.argv) == 2:
        if int(sys.argv[1]) == 0:
            info = peer_b
            notifier_config = {
                'name': "Peer B",
                'rate': 5,
                'identity': {
                    'name': "Peer B",
                    'ip': "127.0.0.1",
                    'node_port': 9877,
                    'server_port': 0
                }
            }
        elif int(sys.argv[1]) == 1:
            info = peer_c
            notifier_config = {
                'name': "Peer C",
                'rate': 5,
                'identity': {
                    'name': "Peer C",
                    'ip': "127.0.0.1",
                    'node_port': 9878,
                    'server_port': 0
                }
            }
        else:
            print("Unrecognized input, exiting")
            sys.exit(1)
    else:
        print("Unrecognized input, exiting")
        sys.exit(1)

    # Set up the node
    node = FileSharingNode(info[0], info[1], id=info[2])
    not_serv = AuditNotifier.AuditNotifier(notifier_config, do_nothing)

    node.start()
    not_serv.start()

    command = input("? ")
    while command != "stop":
        parts = command.split(" ", 1)
        if parts[0] == "help":
            print_help()
        elif parts[0] == "connect":
            if len(parts) == 2:
                connect_to_node(node)
                # connect_to_node(parts[1])
            else:
                connect_to_node(node)
                # print("Please provide a node address to connect to")
        elif parts[0] == "disconnect":
            if len(parts) == 2:
                disconnect_node(node)
                # disconnect_node(parts[1])
            else:
                disconnect_node(node)
                # print("Please provide a node address to disconnect")
        elif parts[0] == "stats":
            node.get_stats()
        elif parts[0] == "msg_enc":
            if len(parts) == 2:
                send_enc_msg(node, parts[1])
            else:
                print("Please provide a message to send an encrypted test message")

        command = input("? ")

    node.stop()
    not_serv.stop()
