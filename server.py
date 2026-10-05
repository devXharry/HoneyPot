import socket

s = socket.socket()
print("Socket succesfully created")

port = 12345

s.bind(('', port))
print("socket binded to %s" %(port))

s.listen(5)
print("Socket is listening")

while True:
    c, addr = s.accept()
    print('Got Connection from', addr)

    c.send('Thank you for connection'.encode())
    c.close()

    break

s.close()