import pymerkle
import datetime
import hashlib
import json
import time

import AuditData
import BlockChain

class Node:
    def __init__(self, name):
        self.name = name
        self.audit_data = None
        self.blockchain = None
        self.root = None

    def add_peer_node(self):
        print("Add_Peer_Node:: Not implemented")

    def remove_peer_node(self):
        print("Remove_Peer_Node:: Not implemented")

    def update_block_chain(self, user_id, new_record):
        if not self.audit_data.add_to_user(user_id, new_record):
            print("Node:: update_block_chain: Failed to add to user record, no user found.")
            return False

        p_block = self.blockchain.create_block(
            self.audit_data.get_audit_root()
        )

        # Add the consensus stuff here...

        self.blockchain.add_block(p_block)

        return True

    def prove_update(self):
        print("Prove_Update:: Not implemented")

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
    node = Node('NodeA')

    node.build_node_trees(a)

    print(node.blockchain)
    print(node.audit_data)

    time.sleep(1)

    action_a = {
        'user': "Colton",
        'action': 'Read a thing',
        'signature': b'F0F0F0F0'.hex()
    }
    node.update_block_chain('testid_1', json.dumps(action_a, indent=2))

    time.sleep(1)
    node.update_block_chain('testid_1', json.dumps(action_a, indent=2))

    print(node.blockchain)
    print(node.audit_data)



