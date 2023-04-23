import pymerkle
import datetime
import json

class AuditData:
    def __init__(self):
        self.user_trees = []
        self.user_dict = {}
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
        for user_key in self.user_dict.keys():
            if user_key == user_id:
                found_flag = True
                break

        if found_flag:
            return self.user_dict[user_id].root
        else:
            return None

    def create_user_action(self, user_id, action):
        new_action = {
            'user_id': user_id,
            'timestamp': str(datetime.datetime.now()),
            'action': action
        }

        return json.dumps(new_action, indent=2).encode('utf-8')

    def add_user(self, user_id):
        new_user = self.create_user_action(
            user_id,
            'Create'
        )

        new_user_tree = pymerkle.MerkleTree(
            algorithm='sha256',
            encoding='utf-8',
            security=True)

        new_user_tree.append_entry(new_user)

        self.user_trees.append(new_user_tree)
        self.user_dict[user_id] = new_user_tree

    def add_to_user(self, user_id, action):
        found_flag = False
        user_key = None

        for user_key in self.user_dict.keys():
            if user_key == user_id:
                found_flag = True
                break

        if found_flag:
            user_tree = self.user_dict[user_key]
            new_entry = self.create_user_action(user_id, action)
            user_tree.append_entry(new_entry)

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


if __name__ == "__main__":
    in_a = ['testid_1', 'testid_2', 'testid_3', 'testid_4']

    audit_data = AuditData()
    audit_data.initialize_audit_data(in_a)

    print(audit_data)

    audit_data.add_to_user('testid_2', 'READ')

    print(audit_data)



