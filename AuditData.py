import pymerkle
import datetime
import json

class AuditData:
    def __init__(self):
        self.user_trees = []
        self.user_tree_dict = {}
        self.user_entry_dict = {}
        self.audit_tree = None

    def __str__(self):
        tree_str = self.audit_tree_print()
        user_str = self.print_user_trees()

        return tree_str + "\n" + user_str

    def print_user_trees(self):
        if len(self.user_trees) == 0:
            return "User Trees: None"

        user_strings = []

        for idx, user_tree in enumerate(self.user_trees):
            user_str = "User {}".format(idx)
            user_str = user_str + "\n\tLength:{}".format(user_tree.length)
            user_str = user_str + "\n\tRoot Hash:{}".format(user_tree.root)

            user_strings.append(user_str)

        ret_str = ""
        for user_string in user_strings:
            ret_str = ret_str + user_string + "\n"

        return ret_str

    def audit_tree_print(self):
        if self.audit_tree is not None:
            ret_str = "Audit Tree: \n"
            ret_str = ret_str + "\tSize:{}\n".format(self.audit_tree.size)
            ret_str = ret_str + "\tLength:{}\n".format(self.audit_tree.length)
            ret_str = ret_str + "\tHeight:{}\n".format(self.audit_tree.height)
            ret_str = ret_str + "\tRoot Hash:{}\n".format(self.audit_tree.root)
        else:
            ret_str = "Audit Tree: None"

        return ret_str

    def initialize_audit_data(self, user_list):
        if len(self.user_trees) != 0:
            print("AuditData:: Initialize: Tree not empty, exiting")
            return 0

        for user in user_list:
            self.add_user(user)

        self.build_audit_tree()

    def get_audit_root(self):
        return self.audit_tree.root

    def get_user_root(self, user_id):
        found_flag = False
        for user_key in self.user_tree_dict.keys():
            if user_key == user_id:
                found_flag = True
                break

        if found_flag:
            return self.user_tree_dict[user_id].root
        else:
            return None

    def create_user_action(self, user_id, action):
        new_action = {
            'user_id': user_id,
            'timestamp': str(datetime.datetime.now()),
            'action': action
        }

        return json.dumps(new_action).encode('utf-8')

    def add_user(self, user_id):
        new_user_action = self.create_user_action(
            user_id,
            'Create'
        )

        new_user_tree = pymerkle.MerkleTree(
            algorithm='sha256',
            encoding='utf-8',
            security=False)

        new_user_hash = new_user_tree.append_entry(new_user_action)
        new_user_entry = {
            'action': new_user_action.hex(),
            'hash': new_user_hash.hex()
        }

        self.user_trees.append(new_user_tree)
        self.user_tree_dict[user_id] = new_user_tree
        self.user_entry_dict[user_id] = [new_user_entry]

    def add_to_user(self, user_id, action):
        found_flag = False
        user_key = None

        for user_key in self.user_tree_dict.keys():
            if user_key == user_id:
                found_flag = True
                break

        if found_flag:
            user_tree = self.user_tree_dict[user_key]
            new_action = self.create_user_action(user_id, action)
            entry_hash = user_tree.append_entry(new_action)
            new_entry = {
                'action': new_action.hex(),
                'hash': entry_hash.hex()
            }

            self.user_entry_dict[user_key].append(new_entry)

            self.build_audit_tree()


        return found_flag

    def build_audit_tree(self):
        audit_tree = pymerkle.MerkleTree(
            algorithm='sha256',
            encoding='utf-8',
            security=False)

        for user_entry in self.user_trees:
            audit_tree.append_entry(user_entry.root)

        self.audit_tree = audit_tree

    def export(self):
        audit_tree_root = self.audit_tree.root.hex()
        user_data_dict = {}

        for user_key in self.user_tree_dict.keys():
            tree_leafs = []
            for leaf_num in range(0, self.user_tree_dict[user_key].length):
                cur_leaf = self.user_tree_dict[user_key].leaf(leaf_num)
                tree_leafs.append(cur_leaf.hex())

            user_entry = self.user_entry_dict[user_key].copy()

            user_dict = {
                'user_id': user_key,
                'root': self.user_tree_dict[user_key].root.hex(),
                'leafs': tree_leafs,
                'data': user_entry
            }

            user_data_dict[user_key] = user_dict

        export_data_dict = {
            'tree_root': audit_tree_root,
            'user_data': user_data_dict
        }

        return export_data_dict

    def import_dict(self, audit_dict):
        self.user_tree_dict = {}
        self.user_trees = []
        self.user_entry_dict = {}

        errors = 0

        # Populate User Data
        user_data_dict = audit_dict['user_data']
        for user_key in user_data_dict.keys():
            user_dict = user_data_dict[user_key]

            print("AuditData:: Import Dict: Importing User: {}".format(user_dict['user_id']))

            user_entry_list = []
            user_tree = pymerkle.MerkleTree(
                algorithm='sha256',
                encoding='utf-8',
                security=False)

            for entry_idx, user_entry in enumerate(user_dict['data']):
                user_act = user_entry['action']
                entry_hash = user_tree.append_entry(bytes.fromhex(user_act))
                user_entry_list.append(user_entry)

                entry_hash_hex = entry_hash.hex()
                if entry_hash_hex != user_entry['hash']:
                    print("AuditData::Import Dict: retrieved user entry does not pass hash check, error")
                    errors = errors + 1

            # Check user tree root versus tree
            if user_dict['root'] != user_tree.root.hex():
                print("AuditData:: Import Dict: Retrieved user root hash does not equal computed hash, error")
                errors = errors + 1

            self.user_trees.append(user_tree)
            self.user_tree_dict[user_key] = user_tree
            self.user_entry_dict[user_key] = user_entry_list

        # Build Audit Tree and compare
        self.build_audit_tree()

        # Check Audit Tree root
        if self.audit_tree.root.hex() != audit_dict['tree_root']:
            print("AuditData:: Import Dict: Generated Audit Tree root does not match store hash, error")
            errors = errors + 1

        if errors > 0:
            print("AuditData:: Import Dict: Importing Audit Data failed due to error.")
            return False
        else:
            print("AuditData:: Import Dict: Successfully imported Audit Data")
            return True


if __name__ == "__main__":
    in_a = ['testid_1', 'testid_2', 'testid_3', 'testid_4']

    audit_data = AuditData()
    audit_data.initialize_audit_data(in_a)

    print(audit_data)

    audit_data.add_to_user('testid_2', 'READ')

    print(audit_data)

    out_dict = audit_data.export()

    audit_data_p = AuditData()
    audit_data_p.import_dict(out_dict)

    print(audit_data_p)


