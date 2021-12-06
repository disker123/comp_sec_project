import socket, threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss


'''
PROTOCOL Specification
P2P - Server listening while logged in
Private key is decrypted with password after login

Client beginning communication:
1. Client sends 'SECUREDROP' string
2. Server responds with its RSA public key(2048 bits)
3. Client generates a 256-bit AES key(CBC), and sends it to server, encrypted with public key
4. Server sends its email signed with its private key
5. Client signs its own email with its private key

'''

class SecureDropServer():
    def __init__(self, host=('127.0.0.1', 12345), key=RSA.generate(2048):
        self.host = host
        self.client_threads = []
        self.private_key = key
        self.public_key = key.public_key()

    def handle_client(self, conn, addr):
        magic_string = 'SECUREDROP'
        magic = conn.recv(len(magic_string))
        if magic != magic_string:
            print('Invalid packet format')
            return

        conn.send(self.private_key.export_key(format='PEM'))
        encrypted_key = conn.recv(256)
        cipher = PKCS1_OAEP.new(self.private_key)

        try:
            aes_key = cipher.decrypt(encrypted_key)

        except ValueError:
            print('Failed to decrypt key')
        

    def handler_loop(self):
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.bind(self.host)
            sock.listen()
            while self.running:
                conn, addr = sock.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.start()
                self.client_threads.append(client_thread)