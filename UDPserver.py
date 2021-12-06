import socket
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sock.bind(('127.0.0.1',12345))

while True:
    data, addr=sock.recvfrom(4096)
    print(str(data))
    prompt = "Do you want to recieve communication from " + str(data.decode('UTF-8') + "y/n ")
    reponse = input(prompt)
    message = bytes(reponse,encoding='utf-8')
    sock.sendto(message, addr)

