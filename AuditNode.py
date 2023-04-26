import threading

import pymerkle
import datetime
import hashlib
import json
import time
from p2pnetwork.node import Node


import AuditData
import BlockChain
import AuditNotifier

RESPONSE_TIMEOUT = 20
VOTE_THRESHOLD = .5


class NodeServerComms(Node):
    def __init__(self, config, func_add_action):
        super(NodeServerComms, self).__init__(
            config['host'],
            config['port'],
            config['name'],
            None,
            0
        )
        self.node_name = config['name']
        self.func_add_action = func_add_action

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
        print("\t(data): {} (type: {})".format(data, type(data)))

        in_dict = data

        if in_dict['action'] == 'ADD_TO_USER':
            user_id = in_dict['data']['user_id']
            user_action = in_dict['data']['action']
            status = self.func_add_action(user_id, user_action)

            resp_data = {
                'action': "RESPONSE",
                'status': status
            }
            resp_json = json.dumps(resp_data, indent=2)
            self.send_to_node(node, resp_json)

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
        print("\t(data): {} (type: {})".format(data, type(data)))

        in_dict = data

        if in_dict['action'] == 'ADD_REQUEST':
            vote = self.func_prove_update(in_dict['data'])

            resp_data = {
                'action': "RESPONSE",
                'vote': vote
            }
            resp_json = json.dumps(resp_data, indent=2)
            self.send_to_node(node, resp_json)
        elif in_dict['action'] == 'RESPONSE':
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
        self.server = NodeServerComms(server_config, self.update_block_chain)

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

    def update_block_chain(self, user_id, new_record):
        if not self.audit_data.add_to_user(user_id, new_record):
            print("Node:: update_block_chain: Failed to add to user record, no user found.")
            return False

        p_block = self.blockchain.create_block(
            self.audit_data.get_audit_root()
        )

        # Add the consensus stuff here...
        self.node.reset_peer_status()

        # Format Data for transit
        out_dict = {
            'action': 'ADD_REQUEST',
            'data': self.blockchain.print_block(p_block)
        }
        out_json = json.dumps(out_dict, indent=2)

        self.node.send_to_peers(out_json)

        # Await responses
        consensus = False
        start_time = time.time()
        cur_time = start_time
        while cur_time - start_time < RESPONSE_TIMEOUT:
            consensus = self.node.check_consensus()
            if consensus:
                print("Conensus Reached")
                break
            print("Conensus Check Failed: {} time".format(cur_time - start_time))
            time.sleep(1)
            cur_time = time.time()

        if consensus:
            self.blockchain.add_block(p_block)
        else:
            return False

        return True

    def prove_update(self, new_block):
        print("Prove_Update:: Not implemented, returning True")
        return True

    def new_node_record(self, in_data_dict):
        print("New_Node_Record: Received new record entry: {}".format(
            in_data_dict
        ))
        if (in_data_dict['node_port'] != 0) and (in_data_dict['node_port'] != self.config['node_port']):
            self.node.connect_with_node(in_data_dict['ip'], in_data_dict['node_port'])
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
    a = ['testid_1', 'testid_2', 'testid_3', 'testid_4']

    node_config = {
        'name': "Node A",
        'ip': "127.0.0.1",
        'node_port': 9876,
        'server_port': 9875
    }

    a_node = AuditNode(node_config)

    a_node.build_node_trees(a)

    print(a_node.blockchain)
    print(a_node.audit_data)

    a_node.start_node()

    time.sleep(30)

    action_a = {
        'user': "Colton",
        'action': 'Read a thing',
        'signature': b'F0F0F0F0'.hex()
    }
    #a_node.update_block_chain('testid_1', json.dumps(action_a, indent=2))

    print(a_node.blockchain)

    a_node.stop_node()



