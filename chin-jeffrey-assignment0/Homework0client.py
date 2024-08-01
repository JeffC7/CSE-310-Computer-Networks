import socket
import sys
import random

emailToName = {
    "hi@gmail.com": "Hi",
    "bye@gmail.com": "Bye",
    "lol@gmail.com": "Lol",
}

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10000)
sock.connect(server_address)

try:
    email = random.choice(list(emailToName.keys()))
    message = b'Q'
    message += bytes(chr(len(email)), 'utf-8')
    message += bytes(email, 'utf-8')
    sock.sendall(message)

    response = sock.recv(1)
    if (response.decode('utf-8') == 'R'):
        nameLengthBytes = sock.recv(1)
        nameLength = int.from_bytes(nameLengthBytes, "big")

        name = sock.recv(nameLength)
        print(name.decode('utf-8'))
                

    # amount_received = 0
    # amount_expected = len(message)

    # while(amount_received < amount_expected):
    #     data = sock.recv(1)
    #     amount_received += len(data)
    #     print('received {!r}'.format(data))
finally:
    sock.close()
