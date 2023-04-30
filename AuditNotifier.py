import json
import threading
import time
import socket
import struct
import sys


class AuditNotifier(threading.Thread):
    class Sender(threading.Thread):
        def __init__(self, name, send_rate, identity):
            super(AuditNotifier.Sender, self).__init__()
            self.send_rate = send_rate
            self.identity = identity
            self.name = name

            self.terminate_flag = threading.Event()

        def run(self):
            while not self.terminate_flag.is_set():
                test_addr_port = ("224.1.1.1", 5007)
                test_payload = json.dumps(self.identity).encode()

                #print("{}: Client sending message".format(self.name))
                client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                client_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
                client_sock.sendto(test_payload, test_addr_port)
                client_sock.close()

                time.sleep(self.send_rate)
            print("{}: Notifier Client Exiting".format(self.name))


            return 0

        def stop(self):
            print("{}: Notifier Client: Requesting Client to stop".format(self.name))
            self.terminate_flag.set()

    class Listener(threading.Thread):
        def __init__(self, handle_data_func):
            super(AuditNotifier.Listener, self).__init__()

            self.terminate_flag = threading.Event()
            self.handle_data_func = handle_data_func

        def run(self):
            while not self.terminate_flag.is_set():
                server = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(('', 5007))
                mreq = struct.pack("4sl", socket.inet_aton("224.1.1.1"), socket.INADDR_ANY)
                server.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

                server.settimeout(5)

                try:
                    bytesAddrPair = server.recvfrom(1024)
                    #print("Recv:: IP: {} | Msg: {}".format(bytesAddrPair[1], bytesAddrPair[0]))

                    self.handle_data_func(bytesAddrPair[0])
                    time.sleep(1)
                except socket.timeout:
                    print("Server recv timeout")

            print("Server Exiting")

            return 0

        def stop(self):
            print("Server: Requesting Server to stop")
            self.terminate_flag.set()

    def __init__(self, config, new_record_func):
        super(AuditNotifier, self).__init__()

        # When this flag is set, the node will stop and close
        self.terminate_flag = threading.Event()

        # Local Variables
        self.peer_list = []
        self.new_record_func = new_record_func
        self.incoming_data = []

        # Notifier Loop
        self.notifier = AuditNotifier.Sender(
            config['name'],
            config['rate'],
            config['identity']
        )
        self.notifier.start()

        # Listener Loop
        self.listener = AuditNotifier.Listener(
            self.received_entry
        )
        self.listener.start()

    def received_entry(self, data: bytes):
        if data not in self.incoming_data:
            self.incoming_data.append(data)

    def parse_entry(self, data: bytes):
        json_data = json.loads(data.decode())
        if json_data not in self.peer_list:
            print("Notifier: Parse Entry: Data ({}) not in List ({})".format(json_data, self.peer_list))
            self.peer_list.append(json_data)
            self.new_record_func(json_data)

    def run(self):
        while not self.terminate_flag.is_set():
            # Do a thing, main state machine
            if self.incoming_data:
                self.parse_entry(self.incoming_data.pop())

            time.sleep(.1)

        print("AuditNotifier:: Stopping...")
        self.notifier.stop()
        self.listener.stop()

        time.sleep(.1)

        self.notifier.join()
        self.listener.join()

    def stop(self):
        print("Server: Requesting Server to stop")
        self.terminate_flag.set()


def do_nothing(variable):
    print("Doing nothing with {}".format(variable))


if __name__ == "__main__":
    if len(sys.argv) == 2:
        if int(sys.argv[1]) == 0:
            notifier_config = {
                'name': "Peer C",
                'rate': 5,
                'identity': {
                    'name': "Peer C",
                    'ip': "127.0.0.1",
                    'port': 9878
                }
            }
        elif int(sys.argv[1]) == 1:
            notifier_config = {
                'name': "Peer B",
                'rate': 5,
                'identity': {
                    'name': "Peer B",
                    'ip': "127.0.0.1",
                    'port': 9877
                }
            }
        else:
            print("Unrecognized input, exiting")
            sys.exit(1)
    else:
        print("Unrecognized input, exiting")
        sys.exit(1)

    not_serv = AuditNotifier(notifier_config, do_nothing)

    not_serv.start()

    command = input("? ")
    while command != "stop":
        command = input("? ")

    not_serv.stop()
