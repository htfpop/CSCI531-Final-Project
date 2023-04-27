import hashlib
import datetime
import json


def get_hash(input_val):
    if type(input_val) == str:
        hash_in = bytes.fromhex(input_val)
    else:
        hash_in = input_val

    hash_val = hashlib.sha256(hash_in).digest()

    return hash_val


class Blockchain:
    def __init__(self):
        self.chain = []

    def __str__(self):
        ret_dict = {}
        for idx, block in enumerate(self.chain):
            ret_dict[idx] = {
                'index': block['index'],
                'timestamp': block['timestamp'],
                'curr_hash': block['curr_hash'].hex(),
                'data_hash': block['data_hash'].hex(),
                'prev_hash': block['prev_hash'].hex()
            }

        ret_str = json.dumps(ret_dict, indent=2)

        return ret_str

    def dedict_block(self, in_dict):
        ret_block = {
            'index': in_dict['index'],
            'timestamp': in_dict['timestamp'],
            'curr_hash': bytes.fromhex(in_dict['curr_hash']),
            'data_hash': bytes.fromhex(in_dict['data_hash']),
            'prev_hash': bytes.fromhex(in_dict['prev_hash'])
        }

        return ret_block

    def dict_block(self, block):
        ret_block = {
            'index': block['index'],
            'timestamp': block['timestamp'],
            'curr_hash': block['curr_hash'].hex(),
            'data_hash': block['data_hash'].hex(),
            'prev_hash': block['prev_hash'].hex()
        }

        return ret_block

    def print_block(self, block):
        ret_block = self.dict_block(block)

        ret_str = json.dumps(ret_block, indent=2)

        return ret_str

    def add_block(self, block):
        if len(self.chain) == 0:
            self.chain.append(block)
        else:
            if self.validate_new_block(block):
                self.chain.append(block)

    def create_block(self, data_hash):
        if len(self.chain) == 0:
            prev_hash = b''
        else:
            prev_hash = self.chain[-1]['curr_hash']

        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'curr_hash': get_hash(data_hash + prev_hash),
            'data_hash': data_hash,
            'prev_hash': prev_hash
        }

        return block

    def prove_chain(self):
        for block_index in range(1, len(self.chain)):
            prev_block = self.chain[block_index - 1]
            cur_block = self.chain[block_index]

            if prev_block['curr_hash'] != cur_block['prev_hash']:
                return False

            if get_hash(cur_block['data_hash'] + cur_block['prev_hash']) != cur_block['curr_hash']:
                return False

        return True

    def prove_new_block(self, new_block_data):
        print(new_block_data)
        new_block = self.dedict_block(new_block_data)

        if self.validate_new_block(new_block):
            return True
        else:
            return False

    def validate_new_block(self, new_block):
        curr_head = self.chain[-1]

        if get_hash(new_block['data_hash'] + curr_head['curr_hash']) != new_block['curr_hash']:
            return False
        else:
            return True

    def import_dict(self, in_dict):
        self.chain = []
        for block_idx in in_dict.keys():
            self.chain.append(self.dedict_block(in_dict[block_idx]))

        if self.prove_chain():
            print("BlockChain::Import Dict: Successfully imported")
            return True
        else:
            print("BlockChain:: Import Dict: Failed to pass block validation")
            return False

    def export(self):
        ret_dict = {}
        for block_idx, block in enumerate(self.chain):
            ret_dict[block_idx] = self.dict_block(block)

        return ret_dict


if __name__ == "__main__":
    blockchain = Blockchain()
    first_str = 'Test1'
    p_block = blockchain.create_block(
        get_hash(first_str.encode())
    )
    blockchain.add_block(p_block)

    p_block = blockchain.create_block(
        get_hash("Test2".encode())
    )
    blockchain.add_block(p_block)

    p_block = blockchain.create_block(
        get_hash("Test3".encode())
    )
    blockchain.add_block(p_block)

    print(blockchain)

    out_dict = blockchain.export()
    print(out_dict)

    blockchain_p = Blockchain()
    in_status = blockchain_p.import_dict(out_dict)

    print(blockchain_p)
