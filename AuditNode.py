import random
import threading

import pymerkle
import datetime
import hashlib
import json
import time
import sys
from p2pnetwork.node import Node
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from hashlib import sha256
import hmac


import AuditData
import BlockChain
import AuditNotifier

RESPONSE_TIMEOUT = 10
VOTE_THRESHOLD = .5

DATA_KEY = b"\x16\x93=f@\x0b\x84\xb9R'\xb7_\x11\xa9\x9a\x1a\x90\xf9\x10=\x17\x94r\x18\x92\xe9<zIk\x07!"
NODE_DATA_KEY = b"\x16\x93=f@\x0b\x84\xb9R'\xb7_\x11\xa9\x9a\x1a\x90\xf9\x10=\x17\x94r\x18\x92\xe9<zIk\x07!"
SERVER_DATA_KEY = b"\x16\x93=f@\x0b\x84\xb9R'\xb7_\x11\xa9\x9a\x1a\x90\xf9\x10=\x17\x94r\x18\x92\xe9<zIk\x07!"
HMAC_KEY = b"L\xc0I\xa8\xf8x\xfc\x12iBuA\xac\xbd\x1a\x08\xe1\x042\xa6u\xbb\xdf0\xb8k\x1e\xba\xc5\xa2\xb3\xd1"

class NodeServerComms(Node):
    def __init__(self, config, func_add_action, func_query_user):
        super(NodeServerComms, self).__init__(
            config['host'],
            config['port'],
            config['name'],
            None,
            0
        )
        self.node_name = config['name']
        self.func_add_action = func_add_action
        self.func_query_user = func_query_user

        self.server_identities = []

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
        print("Data (type: {}): {}".format(type(data), data))

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

        if in_dict['action'] == 'ADD_TO_USER':
            print("Audit Node:: Node Message: Received request from server node ({}) to add user ({})".format(
                node.id,
                in_dict['data']['user_id']))
            user_id = in_dict['data']['user_id']
            user_action = in_dict['data']['action']
            status = self.func_add_action(user_id, user_action)

            resp_data = {
                'action': "RESPONSE",
                'status': status
            }
            resp_json = json.dumps(resp_data, indent=2)
            print("Audit Node:: Node Message: Responding with status ({}) server node ({})".format(
                status,
                node.id))
        elif in_dict['action'] == 'QUERY_USER':
            print("Audit Node:: Node Message: Received query request from server node ({}) for user ({}) data".format(
                node.id,
                in_dict['data']['user_id']))
            user_id = in_dict['data']['user_id']
            user_action = in_dict['data']['action']

            status, data = self.func_query_user(user_id, user_action)

            resp_data = {
                'action': 'USER_QUERY',
                'status': status,
                'data': data
            }
            resp_json = json.dumps(resp_data, indent=2)
        elif in_dict['action'] == 'QUERY_USERS':
            print("Audit Node:: Node Message: Received query request from server node ({}) for all user data".format(
                node.id))
            user_action = in_dict['data']['action']

            status, data = self.func_query_user(None, user_action)

            resp_data = {
                'action': 'USER_QUERY',
                'status': status,
                'data': data
            }
            resp_json = json.dumps(resp_data, indent=2)
        else:
            print("Audit Node:: Node Message: Received unknown request from server.")
            return

        # Encrypt Payload
        nonce = random.randbytes(8).hex().upper()
        signature = digest_data(nonce + resp_json, HMAC_KEY)
        payload = {
            'nonce': nonce,
            'payload': resp_json,
            'signature': signature
        }
        payload_pkg = json.dumps(payload, indent=2)

        payload_bytes = payload_pkg.encode()
        payload_enc = encrypt_data(payload_bytes, SERVER_DATA_KEY).hex().upper()

        self.send_to_node(node, payload_enc)

    def add_server_identity(self, identity):
        self.server_identities.append(identity)

class NodeComms(Node):
    def __init__(self, config, func_prove_update):
        super(NodeComms, self).__init__(
            config['host'],
            config['port'],
            config['name'],
            None,
            0
        )
        self.node_name = config['name']
        self.func_prove_update = func_prove_update

        self.peer_status = {}

    def outbound_node_connected(self, connected_node):
        print("Node ({}):: outbound_node_connected: Connected to peer node: {}".format(
            self.node_name,
            connected_node.id))
        self.add_peer(connected_node)

    def inbound_node_connected(self, connected_node):
        print("Node ({}):: inbound_node_connected: Connected to peer node: {}".format(
            self.node_name,
            connected_node.id))
        self.add_peer(connected_node)

    def outbound_node_disconnected(self, disconnected_node):
        print("Node ({}):: outbound_node_disconnected: Disconnected from peer node: {}".format(
            self.node_name,
            disconnected_node.id))
        self.remove_peer(disconnected_node)

    def inbound_node_disconnected(self, disconnected_node):
        print("Node ({}):: inbound_node_disconnected: Disconnected from peer node: {}".format(
            self.node_name,
            disconnected_node.id))
        self.remove_peer(disconnected_node)

    def node_request_to_stop(self):
        print("Node ({}):: Stop: Node has requested to stop".format(
            self.node_name))

    def update_node_votes(self, node_id, vote):
        if node_id in self.peer_status.keys():
            self.peer_status[node_id]['vote'] = vote
        else:
            print("Node not in peer list")

    def reset_peer_status(self):
        for peer_id in self.peer_status.keys():
            self.update_node_votes(
                peer_id,
                False
            )

    def check_consensus(self):
        approve = 0
        total = len(self.peer_status)
        if total == 0:
            return True

        for peer in self.peer_status:
            if self.peer_status[peer]['vote']:
                approve = approve + 1

        if (approve / total) > VOTE_THRESHOLD:
            return True
        else:
            return False

    def node_message(self, node, data):
        print("Node:: node_message: Recieved message from node: {}".format(node.id))
        print("Data: (Type: {}): {}".format(type(data), data))

        # Decrypt Payload
        in_data_bytes = bytes.fromhex(data)
        data_dec = decrypt_data(in_data_bytes, NODE_DATA_KEY)
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

        if in_dict['action'] == 'ADD_REQUEST':
            print("Audit Node:: Node Message: Received append request from node ({})".format(
                node.id))
            vote = self.func_prove_update(in_dict['data'])

            resp_data = {
                'action': "RESPONSE",
                'vote': vote
            }
            resp_json = json.dumps(resp_data, indent=2)

            # Encrypt Payload
            nonce = random.randbytes(8).hex().upper()
            signature = digest_data(nonce + resp_json, HMAC_KEY)
            payload = {
                'nonce': nonce,
                'payload': resp_json,
                'signature': signature
            }
            payload_pkg = json.dumps(payload, indent=2)

            payload_bytes = payload_pkg.encode()
            payload_enc = encrypt_data(payload_bytes, NODE_DATA_KEY).hex().upper()

            self.send_to_node(node, payload_enc)
        elif in_dict['action'] == 'RESPONSE':
            print("Audit Node:: Node Message: Received response vote ({}) from node ({})".format(
                in_dict['vote'],
                node.id))
            self.update_node_votes(
                node.id,
                in_dict['vote']
            )

    def get_peers(self):
        peer_nodes = self.all_nodes
        unique_nodes = []

        for node in peer_nodes:
            if node not in unique_nodes:
                unique_nodes.append(node)

        return unique_nodes

    def check_new_connection(self, host, port):
        for node in self.get_peers():
            if node.host == host and node.port == str(port):
                print("Audit Node:: Check New Connection: Record already connected")
                return

        # Else, connect
        print("Audit Node:: Check New Connection: Adding connection")
        self.connect_with_node(host, port)

    def add_peer(self, node):
        if node.id not in self.peer_status.keys():
            self.peer_status[node.id] = {
                'node': node.id,
                'status': 'connected',
                'vote': False
            }

    def send_to_peers(self, data):
        # Send to all peers
        for peer in self.get_peers():
            self.send_to_node(peer, data)

    def remove_peer(self, node):
        if node not in self.all_nodes:
            if node.id in self.peer_status.keys():
                self.peer_status.pop(node.id)


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


class AuditNode:
    def __init__(self, config):
        self.audit_data = None
        self.blockchain = None
        self.root = None
        self.config = config

        # Setup Node for handling Audit network
        node_config = {
            'name': config['name'],
            'host': config['ip'],
            'port': config['node_port']
        }
        self.node = NodeComms(node_config, self.prove_update)

        # Setup Node for handling server comms
        server_config = {
            'name': config['name'],
            'host': config['ip'],
            'port': config['server_port']
        }
        self.server = NodeServerComms(
            server_config,
            self.update_block_chain,
            self.query_user
        )

        # Setup Server for Sharing
        notifier_config = {
            'name': config['name'],
            'rate': 5,
            'identity': {
                'name': config['name'],
                'ip': config['ip'],
                'node_port': config['node_port'],
                'server_port': config['server_port']
            }
        }
        self.notifier = AuditNotifier.AuditNotifier(
            notifier_config,
            self.new_node_record
        )

    def start_node(self):
        self.node.start()
        self.server.start()
        self.notifier.start()

    def stop_node(self):
        self.node.stop()
        self.server.stop()
        self.notifier.stop()

        time.sleep(.1)

        self.node.join()
        self.server.join()
        self.notifier.stop()

    def query_user(self, user_id, new_record):
        if user_id:
            # Search for user and report results
            print("Audit Node:: Query User: Received request to query user ({})".format(user_id))

        else:
            # Return all user data
            print("Audit Node:: Query User: Received request to query all users")

        record = self.audit_data.query_user(user_id)

        query = {
            'time': datetime.datetime.now().isoformat(),
            'record': record
        }

        return True, query

    def update_block_chain(self, user_id, new_record):
        new_action = self.audit_data.create_user_action(user_id, new_record)
        new_entry, new_root = self.audit_data.add_to_user(user_id, new_action, test=True)
        if new_entry is None:
            print("Audit Node:: update_block_chain: Failed to add to user record, no user found.")
            return False

        p_block = self.blockchain.create_block(
            new_root
        )

        # Add the consensus stuff here...
        self.node.reset_peer_status()

        # Format Data for transit
        out_dict = {
            'action': 'ADD_REQUEST',
            'data': {
                'block': self.blockchain.dict_block(p_block),
                'entry': new_entry
            }
        }
        resp_json = json.dumps(out_dict, indent=2)

        # Encrypt Payload
        nonce = random.randbytes(8).hex().upper()
        signature = digest_data(nonce + resp_json, HMAC_KEY)
        payload = {
            'nonce': nonce,
            'payload': resp_json,
            'signature': signature
        }
        payload_pkg = json.dumps(payload, indent=2)

        payload_bytes = payload_pkg.encode()
        payload_enc = encrypt_data(payload_bytes, NODE_DATA_KEY).hex().upper()

        self.node.send_to_peers(payload_enc)

        # Await responses
        consensus = False
        start_time = time.time()
        cur_time = start_time
        while cur_time - start_time < RESPONSE_TIMEOUT:
            consensus = self.node.check_consensus()
            if consensus:
                break
            print("Audit Node:: update_block_chain: awaiting consensus: {} time (of {})".format(
                cur_time - start_time, RESPONSE_TIMEOUT))
            time.sleep(1)
            cur_time = time.time()

        if consensus:
            print("Audit Node:: update_block_chain: Consensus Reached")
            self.blockchain.add_block(p_block)
            self.audit_data.add_to_user(user_id, new_action, test=False)
        else:
            print("Audit Node:: update_block_chain: Consensus failed, rejecting add")
            return False

        return True

    def export_node(self, filepath):
        blockchain_dict = self.blockchain.export()
        audit_data_dict = self.audit_data.export()

        node_export_dict = {
            'blockchain': blockchain_dict,
            'audit_data': audit_data_dict
        }

        export_str = json.dumps(node_export_dict, indent=2)

        # Generate HMAC signature
        nonce = random.randbytes(8).hex().upper()
        signature = digest_data(nonce + export_str, HMAC_KEY)
        out_dict = {
            'nonce': nonce,
            'payload': export_str,
            'signature': signature
        }
        export_export_pkg = json.dumps(out_dict, indent=2)

        # Encrypt Output
        export_bytes = export_export_pkg.encode()
        export_encrypt = encrypt_data(export_bytes, DATA_KEY)
        export_encrypt_hex = export_encrypt.hex()

        with open(filepath, "w") as out_file:
            out_file.write(export_encrypt_hex)

        print("Audit Node:: Export Node: Exported node successful")

    def import_node(self, filepath):
        in_data = None
        with open(filepath, "r") as in_file:
            in_data = in_file.read()

        if in_data:
            # Decrypt
            in_data_bytes = bytes.fromhex(in_data)
            data_decrypt = decrypt_data(in_data_bytes, DATA_KEY)

            try:
                plaintext_str = data_decrypt.decode()
            except UnicodeDecodeError:
                print("Audit Node:: Import Node: Import node failed to import.")
                return False

            # Check HMAC
            plaintext_dict = json.loads(plaintext_str)
            in_nonce = plaintext_dict['nonce']
            in_sig = plaintext_dict['signature']
            in_payload = plaintext_dict['payload']
            new_sig = digest_data(in_nonce + in_payload, HMAC_KEY)
            if not hmac.compare_digest(in_sig, new_sig):
                print("Audit Node:: Import Node: Imported node data failed to import.")
                return False

            in_dict = json.loads(in_payload)
            self.audit_data = AuditData.AuditData()
            self.audit_data.import_dict(in_dict['audit_data'])

            self.blockchain = BlockChain.Blockchain()
            self.blockchain.import_dict(in_dict['blockchain'])

            return True
        else:
            print("Import Node:: No Data read in, exiting")
            return False

    def prove_update(self, new_entry_data):
        print("Prove_Update:: Starting")
        new_block = new_entry_data['block']
        new_entry = new_entry_data['entry']

        # Test against Blockchain
        if not self.blockchain.prove_new_block(new_block):
            print("Audit Node:: Prove Update: New entry failed block check, rejecting")
            return False
        print("Audit Node:: Prove Update: New block validated against blockchain")

        # Test against Audit Data, add if valid
        if not self.audit_data.prove_update(new_entry):
            print("Audit Node:: Prove Update: New entry failed Audit Data check, rejecting")
            return False
        print("Audit Node:: Prove Update: New Action validated against Audit Data.")

        # Update Blockchain
        self.blockchain.add_block(self.blockchain.dedict_block(new_block))

        print("Audit Node:: Prove Update: Success!")
        return True

    def new_node_record(self, in_data_dict):
        print("New_Node_Record: Received new record entry: {}".format(
            in_data_dict
        ))
        if (in_data_dict['node_port'] != 0) and (in_data_dict['node_port'] != self.config['node_port']):
            self.node.check_new_connection(in_data_dict['ip'], in_data_dict['node_port'])
        if in_data_dict['server_port'] != 0 and (in_data_dict['node_port'] != self.config['server_port']):
            self.server.add_server_identity(in_data_dict)

    def build_node_trees(self, user_ids):
        self.audit_data = AuditData.AuditData()
        self.audit_data.initialize_audit_data(user_ids)

        self.blockchain = BlockChain.Blockchain()
        audit_root = self.audit_data.get_audit_root()
        p_block = self.blockchain.create_block(
            audit_root
        )
        self.blockchain.add_block(p_block)


if __name__ == "__main__":
    a = ['400943', '328510', 'testid_3', 'testid_4']

    node_config_a = {
        'name': "Node A",
        'ip': "127.0.0.1",
        'node_port': 9876,
        'server_port': 9875
    }

    node_config_b = {
        'name': "Node B",
        'ip': "127.0.0.1",
        'node_port': 9871,
        'server_port': 9870
    }

    if len(sys.argv) == 2:
        if int(sys.argv[1]) == 0:
            config = node_config_a
        elif int(sys.argv[1]) == 1:
            config = node_config_b
        else:
            print("Unrecognized input, exiting")
            sys.exit(1)
    else:
        config = node_config_a

    a_node = AuditNode(config)

    if not a_node.import_node("./node_a_export.enc"):
        print("File failed to import.")
        a_node.start_node()
        a_node.stop_node()
        sys.exit(1)

    print(a_node.blockchain)
    print(a_node.audit_data)

    a_node.start_node()

    command = input("? ")
    while command != "stop":
        if command == "update":
            action_a = {
                'user': "Colton",
                'action': 'Read a thing',
                'signature': b'F0F0F0F0'.hex()
            }
            a_node.update_block_chain('testid_1', json.dumps(action_a, indent=2))
        if command == "print":
            print(a_node.blockchain)
            print(a_node.audit_data)
        if command == "save":
            a_node.export_node("./node_a_export.enc")
        if command == "new_user":
            action_a = {
                'user': "Colton",
                'action': 'Read a thing',
                'signature': b'F0F0F0F0'.hex()
            }
            a_node.update_block_chain('Colton', json.dumps(action_a, indent=2))
        command = input("? ")

    print("Node exiting")

    a_node.stop_node()



