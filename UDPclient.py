import socket
client_socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

msg = "hello UDP server I am a client"
client_socket.sendto(msg.encode("utf-8"),("127.0.0.1",12345))
data, addr = client_socket.recvfrom(4096)
print("server says")
print(str(data))
client_socket.close()