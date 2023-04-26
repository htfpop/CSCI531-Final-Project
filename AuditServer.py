import threading

import pymerkle
import datetime
import hashlib
import json
import time
from p2pnetwork.node import Node
import random

import AuditNotifier

RESPONSE_TIMEOUT = 20
VOTE_THRESHOLD = .5


class NodeServerComms(Node):
    def __init__(self, host, port, audit_node_name, return_status_func):
        super(NodeServerComms, self).__init__(host, port, audit_node_name, None, 0)
        self.node_name = audit_node_name
        self.report_status_func = return_status_func

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

        if in_dict['action'] == 'RESPONSE':
            status = self.report_status_func(in_dict['status'])


class AuditServer:
    def __init__(self, host, port, server_id, notifier_config):

        self.status = False
        self.node_identities = []
        self.port = port

        # Start Node communications
        self.server = NodeServerComms(host, port, server_id, self.update_status)

        # Start notification server
        self.not_server = AuditNotifier.AuditNotifier(
            notifier_config,
            self.new_node_record
        )

    def new_node_record(self, in_data_dict):
        print("New_Node_Record: Received new record entry: {}".format(
            in_data_dict
        ))
        if (in_data_dict['server_port'] != 0) and (in_data_dict['server_port'] != self.port):
            self.node_identities.append(in_data_dict)

    def update_status(self, status):
        self.status = status

    def append_user_record(self, user_id, action):
        self.update_status(False)

        payload = {
            'action': "ADD_TO_USER",
            'data': {
                'user_id': user_id,
                'action': action
            }
        }
        payload_json = json.dumps(payload, indent=2)
        self.server.send_to_nodes(payload_json)

        # Choose random node to communicate with
        if len(self.node_identities) == 0:
            print("Server Failure: No nodes to communicate with, error. ")
            return False

        node_choice = random.choice(self.node_identities)

        print("Append User: Sending to Node: {}".format(node_choice))

        self.server.connect_with_node(node_choice['ip'], node_choice['server_port'])
        time.sleep(1)
        self.server.send_to_nodes(payload_json)

        timeout = 20
        idx = 0
        while (self.status is False) and (idx < timeout):
            print("Waiting on return status")
            idx = idx + 1
            time.sleep(1)

        if self.status:
            print("Server Success: Record added to blockchain")
            return True
        else:
            print("Server Failure: Record not added, error.")
            return False

    def start(self):
        print("Server: Starting Server Nodes")
        self.server.start()
        self.not_server.start()

    def stop_server(self):
        print("Server: Stopping Server Nodes...")
        self.server.stop()
        self.not_server.stop()

        time.sleep(.1)

        self.server.join()
        self.not_server.stop()
        print("Server: Server Nodes stopped.")


if __name__ == "__main__":
    locl_host = "127.0.0.1"
    locl_port = 9890
    name = "Server A"

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

    time.sleep(10)

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

    aserver.stop_server()







