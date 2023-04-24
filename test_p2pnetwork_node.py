from p2pnetwork.node import Node
import json
import sys


class FileSharingNode(Node):

    def __init__(self, host, port, id=None, callback=None, max_connections=0):
        super(FileSharingNode, self).__init__(host, port, id, callback, max_connections)

    def outbound_node_connected(self, connected_node):
        print("outbound_node_connected: " + connected_node.id)

    def inbound_node_connected(self, connected_node):
        print("inbound_node_connected: " + connected_node.id)

    def inbound_node_disconnected(self, connected_node):
        print("inbound_node_disconnected: " + connected_node.id)

    def outbound_node_disconnected(self, connected_node):
        print("outbound_node_disconnected: " + connected_node.id)

    def node_message(self, connected_node, data):
        print("Node:: node_message: Recieved message from node: {}".format(connected_node.id))
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

    def node_disconnect_with_outbound_node(self, connected_node):
        print("node wants to disconnect with oher outbound node: " + connected_node.id)

    def node_request_to_stop(self):
        print("node is requested to stop!")


# The method prints the help commands text to the console
def print_help():
    print("Test Node App: Accepts connection and echos back approved requests.")
    print("stop - Stops the application.")
    print("connect - Conects to main node (8766).")
    print("disconnect - disconnects from main node (8766)")


def connect_to_node(in_node: FileSharingNode):
    host = "localhost"
    port = 9876
    in_node.connect_with_node(host, port)


def disconnect_node(in_node: FileSharingNode):
    for c_node in in_node.all_nodes:
        in_node.disconnect_with_node(c_node)


if __name__ == "__main__":
    peer_b = ["127.0.0.1", 9877, 'Peer_B']
    peer_c = ["127.0.0.1", 9878, 'Peer_C']

    if len(sys.argv) == 2:
        if int(sys.argv[1]) == 0:
            info = peer_b
        elif int(sys.argv[1]) == 1:
            info = peer_c
        else:
            print("Unrecognized input, exiting")
            sys.exit(1)
    else:
        info = peer_b

    # Setup the node
    node = FileSharingNode(info[0], info[1], id=info[2])

    node.start()

    command = input("? ")
    while command != "stop":
        if command == "help":
            print_help()
        if command == "connect":
            connect_to_node(node)
        if command == "disconnect":
            disconnect_node(node)

        command = input("? ")

    node.stop()


