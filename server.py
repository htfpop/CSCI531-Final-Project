import socket

# create a TCP/IP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# bind the socket to a specific IP address and port
server_address = ('localhost', 8888)
server_socket.bind(server_address)

# listen for incoming connections
server_socket.listen(1)
print('Server is listening on', server_address)

while True:
    # wait for a connection
    client_socket, client_address = server_socket.accept()
    print('[Server]: Received connection from', client_address)

    # receive the message from the client
    message = client_socket.recv(1024).decode()
    print('[Server]: Received message:', message)
    separate = message.split(',')

    # send the response back to the client
    response = 'Hello, ' + separate[0]
    client_socket.sendall(response.encode())
    print('[Server]: Sent response: \"{response}\"')

    # close the connection
    client_socket.close()
