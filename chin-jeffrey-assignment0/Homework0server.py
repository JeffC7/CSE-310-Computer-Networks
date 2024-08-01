import socket
import sys

emailToName = {
    "hi@gmail.com": "Hi",
    "bye@gmail.com": "Bye",
    "lol@gmail.com": "Lol",
}

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 10000)
sock.bind(server_address)

sock.listen(1)

while True: 
    connection, client_address = sock.accept()
    try: 
        while True:
            message = ""
            query = connection.recv(1)
            if query:
                print('received {!r}'.format(query))
                if (query.decode('utf-8') == 'Q'):
                    message += 'R'
                
                emailLengthBytes = connection.recv(1)
                emailLength = int.from_bytes(emailLengthBytes, "big")
                
                email = connection.recv(emailLength)
                name = emailToName[email.decode('utf-8')]
                message += str(len(name))
                message += name
                connection.sendall(message.encode('utf-8'))
            else:
                print('no more data from', client_address)
                break
    finally:
        connection.close()


