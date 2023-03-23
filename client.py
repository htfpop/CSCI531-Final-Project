import socket
import stdiomask

def main():
    print("---Client---")
    email = input("[Client]: Enter Email: ")
    password = stdiomask.getpass(prompt="[Client]: Password:", mask="*")
    print(f'[DEBUG]: {email}:{password}')
    client_handler(email, password)


def client_handler(email, password):
    # create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connect the socket to the server's IP address and port
    server_address = ('localhost', 8888)
    client_socket.connect(server_address)

    # send the message to the server
    message = email+','+password
    client_socket.sendall(message.encode())

    # receive the response from the server
    response = client_socket.recv(1024)
    print(f'[Client.py]: {response.decode()}')

    # close the socket
    client_socket.close()


if __name__ == "__main__":
    main()
