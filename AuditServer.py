import threading

import pymerkle
import datetime
import hashlib
import json
import time
from p2pnetwork.node import Node


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
    def __init__(self, host, port, server_id):
        self.server = NodeServerComms(host, port, server_id, self.update_status)
        self.status = False

        self.server.start()

    def update_status(self, status):
        self.status = status

    def start(self):
        node_ip = "localhost"
        node_port = 9886

        self.server.connect_with_node(node_ip, node_port)
        payload = {
            'action': "ADD_TO_USER",
            'data': {
                'user_id': "testid_1",
                'action': "Add to user thing"
            }
        }
        payload_json = json.dumps(payload, indent=2)
        self.server.send_to_nodes(payload_json)

        timeout = 20
        idx = 0
        while (self.status is False) and (idx < timeout):
            print("Waiting on return status")
            idx = idx + 1
            time.sleep(1)

        print("Server success")
        self.server.stop()

        print("Server exiting")

        return 0


if __name__ == "__main__":
    locl_host = "127.0.0.1"
    locl_port = 9875
    name = "Server A"
    aserver = AuditServer(locl_host, locl_port, name)

    aserver.start()





