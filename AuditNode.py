import pymerkle
import datetime
import hashlib
import json
import time
from p2pnetwork.node import Node


import AuditData
import BlockChain

RESPONSE_TIMEOUT = 20
VOTE_THRESHOLD = .5

class AuditNode(Node):
    def __init__(self, host, port, audit_node_name):
        super(AuditNode, self).__init__(host, port, audit_node_name, None, 0)
        self.audit_data = None
        self.blockchain = None
        self.root = None

        self.peer_status = {}

    def outbound_node_connected(self, connected_node):
        print("Node:: outbound_node_connected: Connected to peer node: {}".format(connected_node.id))
        self.add_peer(connected_node)

    def inbound_node_connected(self, connected_node):
        print("Node:: inbound_node_connected: Connected to peer node: {}".format(connected_node.id))
        self.add_peer(connected_node)

    def outbound_node_disconnected(self, disconnected_node):
        print("Node:: outbound_node_disconnected: Disconnected from peer node: {}".format(disconnected_node.id))
        self.remove_peer(disconnected_node)

    def inbound_node_disconnected(self, disconnected_node):
        print("Node:: inbound_node_disconnected: Disconnected from peer node: {}".format(disconnected_node.id))
        self.remove_peer(disconnected_node)

    def node_message(self, node, data):
        print("Node:: node_message: Recieved message from node: {}".format(node.id))
        print("\t(data): {} (type: {})".format(data, type(data)))

        in_dict = data

        if in_dict['action'] == 'ADD_REQUEST':
            vote = self.prove_update(in_dict['data'])

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


    def node_request_to_stop(self):
        print("Node:: Stop: Node has requested to stop")

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

    def remove_peer(self, node):
        if node not in self.all_nodes:
            if node.id in self.peer_status.keys():
                self.peer_status.pop(node.id)

    def update_node_votes(self, node_id, vote):
        if node_id in self.peer_status.keys():
            self.peer_status[node_id]['vote'] = vote
        else:
            print("Node not in peer list")

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

    def update_block_chain(self, user_id, new_record):
        if not self.audit_data.add_to_user(user_id, new_record):
            print("Node:: update_block_chain: Failed to add to user record, no user found.")
            return False

        p_block = self.blockchain.create_block(
            self.audit_data.get_audit_root()
        )

        # Add the consensus stuff here...
        for peer_id in self.peer_status.keys():
            self.update_node_votes(
                peer_id,
                False
            )

        # Format Data for transit
        out_dict = {
            'action': 'ADD_REQUEST',
            'data': self.blockchain.print_block(p_block)
        }
        out_json = json.dumps(out_dict, indent=2)

        # Send to all peers
        for peer in self.get_peers():
            self.send_to_node(peer, out_json)

        # Await responses
        consensus = False
        start_time = time.time()
        cur_time = start_time
        while ((cur_time - start_time < RESPONSE_TIMEOUT)):
            consensus = self.check_consensus()
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

    node_ip = "127.0.0.1"
    node_port = 9876

    a_node = AuditNode(node_ip, node_port, 'NodeA')

    a_node.build_node_trees(a)

    print(a_node.blockchain)
    print(a_node.audit_data)

    a_node.start()

    time.sleep(10)

    action_a = {
        'user': "Colton",
        'action': 'Read a thing',
        'signature': b'F0F0F0F0'.hex()
    }
    a_node.update_block_chain('testid_1', json.dumps(action_a, indent=2))

    print(a_node.blockchain)

    a_node.stop()



