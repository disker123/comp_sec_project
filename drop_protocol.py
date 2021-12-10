import socket, threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss

#import pdb

'''
PROTOCOL Specification
P2P - Server listening while logged in
Private key is decrypted with password after login

Client beginning communication:
1. Client sends 'SECUREDROP' string
2. Client responds with its RSA public key
3. Server responds with its RSA public key(2048 bits)
4. Client generates a 256-bit AES key(CBC), and sends it to server followed by 16-byte nonce, encrypted with public key
-- All further communication is encrypted with this key --
5. Server sends its email signed with its private key
6. Client sends its email signed with its private key
7. Client sends command id as single byte

'''

magic_string = b'SECUREDROP'
COMMAND_PING = b'\x00'
COMMAND_SEND = b'\x01'

class SecureDropServer(threading.Thread):
    def __init__(self, config, host=('127.0.0.1', 12345)):
        threading.Thread.__init__(self)
        self.config = config
        self.host = host

    def handle_client(self, conn, addr):
        try:
            with conn:
                magic = conn.recv(len(magic_string))
                if magic != magic_string:
                    print('Invalid packet format')
                    return

                client_key = conn.recv(2048)
                client_key = RSA.import_key(client_key)

                # TODO check certificate

                conn.send(self.config.key.public_key().export_key(format='PEM'))
                
                encrypted_key = conn.recv(256)
                encrypted_nonce = conn.recv(256)
                cipher = PKCS1_OAEP.new(self.config.key)

                aes_key = cipher.decrypt(encrypted_key)
                nonce = cipher.decrypt(encrypted_nonce)

                decryptor = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
                encryptor = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
                email = bytes(self.config.email, 'utf8')
                
                #pdb.set_trace()
                h = SHA256.new(email)
                sig = pss.new(self.config.key).sign(h)
                conn.send(encryptor.encrypt(sig))
                conn.send(encryptor.encrypt(email))

                #pdb.set_trace()

                sig = decryptor.decrypt(conn.recv(256))
                client_email = decryptor.decrypt(conn.recv(320)).rstrip(b'\x00')
                verifier = pss.new(client_key)
                verifier.verify(SHA256.new(client_email), sig)

                #TODO check if in contacts
                
                cmd = decryptor.decrypt(conn.recv(1))
                if cmd == COMMAND_PING:
                    print('Ping from ' + client_email.decode())
                    conn.send(encryptor.encrypt(COMMAND_PING))
                else:
                    print('Invalid command recieved from ' + client_email.decode())
        except (ValueError, TypeError):
            print('Failed to decrypt message')

    def bind(self, host):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(host)

    def run(self):
        with self.sock as sock:
            sock.bind(self.host)
            sock.listen()
            self.running = True
            while self.running:
                conn, addr = sock.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.start()
                self.client_threads.append(client_thread)

            for th in self.client_threads:
                th.join()


class SecureDropClient:
    def __init__(self, config):
        self.config = config
        pass

    def connect(self, email, host):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock = sock
        try:
            sock.connect(host)
            sock.send(magic_string)
            sock.send(self.public_key.export_key(format='PEM'))

            server_key = RSA.import_key(sock.recv(2048))

            aes_key = get_random_bytes(32)
            encryptor = AES.new(aes_key, AES.MODE_EAX)
            nonce = encryptor.nonce
            decryptor = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            cipher = PKCS1_OAEP.new(server_key)
            encrypted_key = cipher.encrypt(aes_key) 
            encrypted_nonce = cipher.encrypt(nonce)
            
            sock.send(encrypted_key)
            sock.send(encrypted_nonce)

            #pdb.set_trace()
            sig = decryptor.decrypt(sock.recv(256))
            server_email = decryptor.decrypt(sock.recv(320)).rstrip(b'\x00')

            verifier = pss.new(server_key)
            verifier.verify(SHA256.new(server_email), sig)

            if server_email.decode().lower() != email.lower():
                sock.close()
                return False

            #pdb.set_trace()
            email = bytes(self.config.email, 'utf8')
            sig = pss.new(self.config.key).sign(SHA256.new(email))
            sock.send(encryptor.encrypt(sig))
            sock.send(encryptor.encrypt(email))

            self.decryptor = decryptor
            self.encryptor = encryptor
            self.server_email = server_email
            self.server_key = server_key
            return True
        
        except (ValueError, TypeError):
            print('Failed to decrypt message')
        
        return False

    def ping(self, email='server@email.com', host=('127.0.0.1', 12345)):
        if self.connect(email, host):
            with self.sock:
                self.sock.send(self.encryptor.encrypt(COMMAND_PING))
                return COMMAND_PING == self.decryptor.decrypt(self.sock.recv(1))

        return False