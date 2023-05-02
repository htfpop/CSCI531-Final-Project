import threading

import pymerkle
import datetime
import hashlib
import json
import time
from p2pnetwork.node import Node
import random
from hashlib import sha256
import hmac
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import AuditNotifier

RESPONSE_TIMEOUT = 20
VOTE_THRESHOLD = .5

SERVER_DATA_KEY = b"\x16\x93=f@\x0b\x84\xb9R'\xb7_\x11\xa9\x9a\x1a\x90\xf9\x10=\x17\x94r\x18\x92\xe9<zIk\x07!"
HMAC_KEY = b"L\xc0I\xa8\xf8x\xfc\x12iBuA\xac\xbd\x1a\x08\xe1\x042\xa6u\xbb\xdf0\xb8k\x1e\xba\xc5\xa2\xb3\xd1"

def encrypt_data(data_in, key):
    cipher = Cipher(algorithms.AES256(key), modes.ECB())
    padder = padding.PKCS7(256).padder()

    encryptor = cipher.encryptor()
    padder_data = padder.update(data_in)
    padder_data += padder.finalize()

    ct_out = encryptor.update(padder_data) + encryptor.finalize()

    return ct_out


def decrypt_data(ct_in, key):
    cipher = Cipher(algorithms.AES256(key), modes.ECB())
    unpadder = padding.PKCS7(256).unpadder()

    decryptor = cipher.decryptor()
    pt = decryptor.update(ct_in) + decryptor.finalize()

    unpadderdata = unpadder.update(pt)
    unpadderdata += unpadder.finalize()

    pt_out = unpadderdata

    return pt_out


def digest_data(message, key):
    signature = hmac.new(
        key,
        msg=message.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

    return signature


class NodeServerComms(Node):
    def __init__(self, host, port, audit_node_name, return_status_func, report_query_status_func):
        super(NodeServerComms, self).__init__(host, port, audit_node_name, None, 0)
        self.node_name = audit_node_name
        self.report_status_func = return_status_func
        self.report_query_status_func = report_query_status_func

    def outbound_node_connected(self, connected_node):
        print("Node ({}):: outbound_node_connected: Connected to peer node: {}".format(
            self.node_name,
            connected_node.id))

    def inbound_node_connected(self, connected_node):
        print("Node ({}):: inbound_node_connected: Connected to peer node: {}".format(
            self.node_name,
            connected_node.id))

    def outbound_node_disconnected(self, disconnected_node):
        print("Node ({}):: outbound_node_disconnected: Disconnected from peer node: {}".format(
            self.node_name,
            disconnected_node.id))

    def inbound_node_disconnected(self, disconnected_node):
        print("Node ({}):: inbound_node_disconnected: Disconnected from peer node: {}".format(
            self.node_name,
            disconnected_node.id))

    def node_request_to_stop(self):
        print("Node ({}):: Stop: Node has requested to stop".format(
            self.node_name))

    def node_message(self, node, data):
        print("Node:: node_message: Recieved message from node: {}".format(node.id))

        # Decrypt Payload
        in_data_bytes = bytes.fromhex(data)
        data_dec = decrypt_data(in_data_bytes, SERVER_DATA_KEY)
        in_plaintext = data_dec.decode()
        in_payload_pkg = json.loads(in_plaintext)

        # Break apart Payload
        in_nonce = in_payload_pkg['nonce']
        in_sig = in_payload_pkg['signature']
        in_payload = in_payload_pkg['payload']
        new_sig = digest_data(in_nonce + in_payload, HMAC_KEY)
        if not hmac.compare_digest(in_sig, new_sig):
            print("Node: Recieved message failed integrity check")
            return

        in_dict = json.loads(in_payload)
        print("In Dict (type: {}): {}".format(type(in_dict), in_dict))

        if in_dict['action'] == 'RESPONSE':
            self.report_status_func(in_dict['status'])
        elif in_dict['action'] == 'USER_QUERY':
            self.report_query_status_func(
                in_dict['status'],
                in_dict['data']
            )


class AuditServer:
    def __init__(self, host, port, server_id, notifier_config):

        self.status = False
        self.q_status = False
        self.q_payload = None
        self.node_identities = []
        self.port = port

        # Start Node communications
        self.server = NodeServerComms(host, port, server_id, self.update_status, self.query_status)

        # Start notification server
        self.not_server = AuditNotifier.AuditNotifier(
            notifier_config,
            self.new_node_record
        )

    def new_node_record(self, in_data_dict):
        print("Audit Server:: New_Node_Record: Received new record entry: {}".format(
            in_data_dict
        ))
        if (in_data_dict['server_port'] != 0) and (in_data_dict['server_port'] != self.port):
            self.node_identities.append(in_data_dict)

    def update_status(self, status):
        self.status = status

    def query_status(self, status, payload):
        self.q_status = status
        self.q_payload = payload

    def query_users(self, action):
        self.query_status(False, None)

        out_request = {
            'action': 'QUERY_USERS',
            'data': {
                'action': action
            }
        }

        payload_json = json.dumps(out_request, indent=2)

        # Encrypt Payload
        nonce = random.randbytes(8).hex().upper()
        signature = digest_data(nonce + payload_json, HMAC_KEY)
        payload = {
            'nonce': nonce,
            'payload': payload_json,
            'signature': signature
        }
        payload_pkg = json.dumps(payload, indent=2)

        payload_bytes = payload_pkg.encode()
        payload_enc = encrypt_data(payload_bytes, SERVER_DATA_KEY).hex().upper()

        if self.perform_query(payload_enc):
            print("Audit Server:: Query Users: Successfully retrieved all user data")
        else:
            print("Audit Server:: Query Users: Failed to retrieve all user data")

        return self.q_payload

    def query_user(self, user_id, action):
        self.query_status(False, None)

        out_request = {
            'action': "QUERY_USER",
            'data': {
                'user_id': user_id,
                'action': action
            }
        }

        payload_json = json.dumps(out_request, indent=2)

        # Encrypt Payload
        nonce = random.randbytes(8).hex().upper()
        signature = digest_data(nonce + payload_json, HMAC_KEY)
        payload = {
            'nonce': nonce,
            'payload': payload_json,
            'signature': signature
        }
        payload_pkg = json.dumps(payload, indent=2)

        payload_bytes = payload_pkg.encode()
        payload_enc = encrypt_data(payload_bytes, SERVER_DATA_KEY).hex().upper()

        if self.perform_query(payload_enc):
            print("Audit Server:: Query User: Successfully retrieved user ({})data".format(user_id))
        else:
            print("Audit Server:: Query User: Failed to retrieve user ({}) data".format(user_id))

        return self.q_payload

    def perform_query(self, payload):
        # Choose random node to communicate with
        if len(self.node_identities) == 0:
            print("Audit Server:: Server Failure: No nodes to communicate with, error. ")
            return False

        node_choice = random.choice(self.node_identities)

        print("Audit Server:: Perform Query: Querying from node: {}".format(node_choice))

        self.server.connect_with_node(node_choice['ip'], node_choice['server_port'])
        time.sleep(1)
        self.server.send_to_nodes(payload)

        timeout = 20
        idx = 0
        while (self.q_status is False) and (idx < timeout):
            print("Audit Server:: Perform Query: Waiting on return status")
            idx = idx + 1
            time.sleep(1)

        # Disconnect Node

        if self.q_status:
            print("Audit Server:: Perform Query: Retrieved User Record")
            return True
        else:
            print("Audit Server:: Perform Query: Failed to retrieve User Record")
            return False

    def append_user_record(self, user_id, action):
        self.update_status(False)

        out_request = {
            'action': "ADD_TO_USER",
            'data': {
                'user_id': user_id,
                'action': action
            }
        }
        payload_json = json.dumps(out_request, indent=2)

        # Encrypt Payload
        nonce = random.randbytes(8).hex().upper()
        signature = digest_data(nonce + payload_json, HMAC_KEY)
        payload = {
            'nonce': nonce,
            'payload': payload_json,
            'signature': signature
        }
        payload_pkg = json.dumps(payload, indent=2)

        payload_bytes = payload_pkg.encode()
        payload_enc = encrypt_data(payload_bytes, SERVER_DATA_KEY).hex().upper()

        # Choose random node to communicate with
        if len(self.node_identities) == 0:
            print("Server Failure: No nodes to communicate with, error. ")
            return False

        node_choice = random.choice(self.node_identities)

        print("Audit Server:: Append User: Sending to Node: {}".format(node_choice))

        self.server.connect_with_node(node_choice['ip'], node_choice['server_port'])
        time.sleep(1)
        self.server.send_to_nodes(payload_enc)

        timeout = 20
        idx = 0
        while (self.status is False) and (idx < timeout):
            print("\tWaiting on return status")
            idx = idx + 1
            time.sleep(1)

        if self.status:
            print("Audit Server:: Server Success: Record added to blockchain")
            return True
        else:
            print("Audit Server:: Server Failure: Record not added, error.")
            return False

    def start(self):
        print("Audit Server:: Start: Starting Server Nodes")
        self.server.start()
        self.not_server.start()

    def stop_server(self):
        print("Audit Server:: Stop: Stopping Server Nodes...")
        self.server.stop()
        self.not_server.stop()

        time.sleep(.1)

        self.server.join()
        self.not_server.stop()
        print("Server: Server Nodes stopped.")


if __name__ == "__main__":
    locl_host = "127.0.0.1"
    locl_port = 9890
    name = "Audit Server"

    notifier_config = {
        'name': "Audit Server",
        'rate': 5,
        'identity': {
            'name': "Audit Server",
            'ip': "127.0.0.1",
            'node_port': 0,
            'server_port': 9890
        }
    }

    aserver = AuditServer(locl_host, locl_port, name, notifier_config)

    aserver.start()

    command = input("? ")
    while command != "stop":
        if command == "update":
            action_a = {
                'user': "Colton",
                'action': 'Read a thing',
                'signature': b'F0F0F0F0'.hex()
            }
            user_a = 'testid_1'

            aserver.append_user_record(
                user_a,
                json.dumps(action_a, indent=2)
            )
        if command == "query":
            action_a = {
                'user': "Colton",
                'action': 'Query User',
                'signature': b'F0F0F0F0'.hex()
            }
            user_a = 'testid_1'

            ret_payload = aserver.query_user(user_a, action_a)

            print(ret_payload)
        if command == "query_all":
            action_a = {
                'user': "Colton",
                'action': 'Query All Users',
                'signature': b'F0F0F0F0'.hex()
            }

            ret_payload = aserver.query_users(action_a)

            print(ret_payload)
        command = input("? ")

    aserver.stop_server()







