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

    def prove_update(self, entry_data):
        print("Prove Udpate: {}".format(entry_data))
        entry = {
            'user': entry_data['user'],
            'action': bytes.fromhex(entry_data['action']),
            'proof': entry_data['proof'],
            'root': bytes.fromhex(entry_data['root'])
        }

        # Check Proof
        found_flag = False
        for user_key in self.user_tree_dict.keys():
            if user_key == entry['user']:
                found_flag = True
                break

        if not found_flag:
            print("AuditData:: Prove Update: No User found. Checking New User entry")
            if entry['proof'] != "None":
                print("AuditData:: Prove Update: User not new on peer, inconsistency, rejecting.")
                return False
            else:
                print("AuditData:; Prove Update: New User, generating record")
                user_tree = pymerkle.MerkleTree(
                    algorithm='sha256',
                    encoding='utf-8',
                    security=False)

        else:
            # User exists, check proof
            existing_user_tree = self.user_tree_dict[entry['user']]

            proof_de = pymerkle.MerkleProof.deserialize(entry['proof'])
            try:
                pymerkle.verify_consistency(
                    existing_user_tree.root,
                    entry['root'],
                    proof_de
                )
            except pymerkle.proof.InvalidProof:
                print("AuditData:: Prove Update: Failed on consistency verification, error.")
                return False

            # Replace actual with temp test tree
            user_tree = pymerkle.MerkleTree(
                algorithm='sha256',
                encoding='utf-8',
                security=False)

            user_entry_list = self.user_entry_dict[entry['user']]
            for user_entry in user_entry_list:
                user_action = bytes.fromhex(user_entry['action'])
                user_tree.append_entry(user_action)

        # Add new action to tree
        new_hash = user_tree.append_entry(entry['action'])
        new_entry = {
            'action': entry_data['action'],
            'hash': new_hash
        }

        if user_tree.root != entry['root']:
            print("AuditData:: Prove Update: New User root does not equal supplied root, error")
            return False
        else:
            if not found_flag:
                self.user_entry_dict[entry['user']] = []
                self.user_tree_dict[entry['user']] = user_tree
                self.user_trees.append(user_tree)
            else:
                # Test Passed, Append to real tree
                self.user_tree_dict[entry['user']].append_entry(entry['action'])

            # Add entry to user list
            self.user_entry_dict[entry['user']].append(new_entry)

            # Rebuild Audit Merkle Tree
            self.build_audit_tree()

        return True

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

    def add_to_user(self, user_id, new_action, test=False):
        found_flag = False
        user_key = None
        new_entry_data = None
        new_entry = None
        user_tree_roots = []

        for user_key in self.user_tree_dict.keys():
            if user_key != user_id:
                user_root = self.user_tree_dict[user_key].root
                user_tree_roots.append(user_root)
            else:
                if test:
                    # Replace actual with temp test tree
                    user_tree = pymerkle.MerkleTree(
                        algorithm='sha256',
                        encoding='utf-8',
                        security=False)

                    user_entry_list = self.user_entry_dict[user_key]
                    for user_entry in user_entry_list:
                        user_action = bytes.fromhex(user_entry['action'])
                        user_tree.append_entry(user_action)

                else:
                    # Perform on actual user tree
                    user_tree = self.user_tree_dict[user_key]

                # Get Tree Status Before add
                user_old_root = user_tree.root
                user_old_size = user_tree.length

                # Add to tree
                entry_hash = user_tree.append_entry(new_action)
                new_entry = {
                    'action': new_action.hex(),
                    'hash': entry_hash.hex()
                }

                # Generate Proof
                proof = user_tree.prove_consistency(user_old_size, user_old_root)
                proof_root = user_tree.root
                new_entry_data = {
                    'user': user_key,
                    'action': new_action.hex(),
                    'proof': proof.serialize(),
                    'root': proof_root.hex()
                }

                # Add tree root to list
                user_tree_roots.append(user_tree.root)

                # Set Found Flag
                found_flag = True

        # Tag it or create it
        if not found_flag:
            print("Audit Data:: Add_to_User: Creating new user ({})".format(user_id))
            # Create User
            user_tree = pymerkle.MerkleTree(
                algorithm='sha256',
                encoding='utf-8',
                security=False)

            # Add to tree
            entry_hash = user_tree.append_entry(new_action)
            new_entry = {
                'action': new_action.hex(),
                'hash': entry_hash.hex()
            }

            new_entry_data = {
                'user': user_id,
                'action': new_action.hex(),
                'proof': "None",
                'root': user_tree.root.hex()
            }

            # Add tree root to list
            user_tree_roots.append(user_tree.root)

            # If committing new entry (not test), create data structure entries
            if not test:
                self.user_entry_dict[user_id] = []
                self.user_tree_dict[user_id] = user_tree
                self.user_trees.append(user_tree)

        if not test:
            # If not a test, add action to user entry
            self.user_entry_dict[user_id].append(new_entry)
            audit_root = self.build_audit_tree()
        else:
            audit_root = self.build_audit_root(user_tree_roots)

        return new_entry_data, audit_root

    def build_audit_root(self, user_tree_roots):
        audit_tree = pymerkle.MerkleTree(
            algorithm='sha256',
            encoding='utf-8',
            security=False)

        for tree_root in user_tree_roots:
            audit_tree.append_entry(tree_root)

        return audit_tree.root

    def build_audit_tree(self):
        audit_tree = pymerkle.MerkleTree(
            algorithm='sha256',
            encoding='utf-8',
            security=False)

        for user_entry in self.user_trees:
            audit_tree.append_entry(user_entry.root)

        self.audit_tree = audit_tree

        return audit_tree.root

    def query_user(self, user_id):
        if user_id:
            # Get Specific user record
            found_flag = False
            user_key = None
            entry_idx = 0
            entry = None

            for user_key in self.user_entry_dict.keys():
                if user_key == user_id:
                    found_flag = True
                    break

            if found_flag:
                user_dict = {}

                for entry_idx, entry in enumerate(self.user_entry_dict[user_key]):
                    action = entry['action']
                    action_decode = json.loads(bytes.fromhex(action).decode())  # changed 4/30
                    user_dict[entry_idx] = action_decode

                return user_dict
            else:
                return None
        else:
            all_users_dict = {}
            for user_key in self.user_entry_dict.keys():
                user_dict = {}
                for entry_idx, entry in enumerate(self.user_entry_dict[user_key]):
                    action = entry['action']
                    action_decode = bytes.fromhex(action).decode()
                    user_dict[entry_idx] = action_decode

                all_users_dict[user_key] = user_dict

            return all_users_dict

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
    #in_a = ['testid_1', 'testid_2', 'testid_3', 'testid_4']
    in_a = ['testid_1']
    audit_data = AuditData()
    audit_data.initialize_audit_data(in_a)

    print(audit_data)

    audit_data.add_to_user('testid_1', 'READ')

    print(audit_data)

    out_dict = audit_data.export()

    audit_data_p = AuditData()
    audit_data_p.import_dict(out_dict)

    audit_data_save = audit_data.user_trees[0].root
    audit_data_save_len = audit_data.user_trees[0].length

    entry_b = audit_data.add_to_user('testid_1', 'READ')

    proof = audit_data.user_trees[0].prove_consistency(audit_data_save_len, audit_data_save)
    proof_root = audit_data.user_trees[0].root

    pymerkle.verify_consistency(audit_data_save, proof_root, proof)

    audit_data_p.prove_update(entry_b)

    print(proof.serialize())


    print(audit_data_save)

    print(audit_data_p)


