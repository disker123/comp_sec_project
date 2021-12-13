import socket, threading, struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss

import traceback, os

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
    def __init__(self, config, input_mutex):
        threading.Thread.__init__(self)
        self.config = config
        self.client_threads = []
        self.input_mutex = input_mutex

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
                
                h = SHA256.new(email)
                sig = pss.new(self.config.key).sign(h)
                conn.send(encryptor.encrypt(sig))
                conn.send(encryptor.encrypt(email))

                sig = decryptor.decrypt(conn.recv(256))
                client_email = decryptor.decrypt(conn.recv(320)).rstrip(b'\x00')
                verifier = pss.new(client_key)
                verifier.verify(SHA256.new(client_email), sig)

                #TODO check if in contacts
                
                if not client_email.decode().lower() in self.config.contacts:
                    return False

                conn.send(encryptor.encrypt(b'\x01'))

                contact = self.config.contacts[client_email.decode().lower()]
                cmd = decryptor.decrypt(conn.recv(32))

                if len(cmd) == 0:
                    return False
                if cmd == COMMAND_PING:
                    conn.send(encryptor.encrypt(COMMAND_PING))
                elif cmd == COMMAND_SEND:
                    self.input_mutex.acquire()
                    print('\n')
                    r = ''
                    try:
                        while r != 'y' and r != 'n':
                            r = input("Contact '%s <%s>' is sending a file. Accept(y/n): " % (contact['name'], contact['email']))
                    finally:
                        self.input_mutex.release()

                    if r == 'y':
                        conn.send(encryptor.encrypt(b'\x01'))
                        filename_length = struct.unpack('I', decryptor.decrypt(conn.recv(4)))[0]
                        filename = os.path.basename(decryptor.decrypt(conn.recv(filename_length)).decode())
                        
                        self.input_mutex.acquire()
                        try:
                            out_dir = input('Where do you want to store %s: ' % filename)
                            if not os.path.isdir(out_dir):
                                os.mkdir(out_dir)
                        finally:
                            self.input_mutex.release()

                        loc = os.path.join(out_dir, filename)
                        
                        with open(loc, 'wb') as f:
                            file_size = struct.unpack('Q', decryptor.decrypt(conn.recv(8)))[0]
                            conn.send(encryptor.encrypt(b'\x01'))
                            sig = decryptor.decrypt(conn.recv(256))
                            bytes_gotten = 0
                            h = SHA256.new()

                            
                            while bytes_gotten < file_size:
                                encrypted_chunk = conn.recv(min(1024, file_size - bytes_gotten))
                                chunk = decryptor.decrypt(encrypted_chunk)
                                f.write(chunk)
                                h.update(chunk)
                                bytes_gotten += len(chunk)

                            try:
                                verifier.verify(h, sig)
                                #print('Saved file %s' % loc)
                                conn.send(encryptor.encrypt(b'\x01'))
                            except (ValueError, TypeError):
                                os.remove(loc)
                                conn.send(encryptor.encrypt(b'\x00'))
                    else:
                        conn.send(encryptor.encrypt(b'\x01'))
                else:
                    print('Invalid command recieved from ' + client_email.decode())
        except (ValueError, TypeError, struct.error) as e:
            print('Failed to decrypt message')
            #print(traceback.format_exc())

    def bind(self, host):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(host)

    def run(self):
        with self.sock as sock:
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

    def connect(self, email, host, timeout=5):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        self.sock = sock
        try:
            sock.connect(host)
            sock.send(magic_string)
            sock.send(self.config.key.public_key().export_key(format='PEM'))

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

            sig = decryptor.decrypt(sock.recv(256))
            server_email = decryptor.decrypt(sock.recv(320)).rstrip(b'\x00')

            verifier = pss.new(server_key)
            verifier.verify(SHA256.new(server_email), sig)

            if server_email.decode().lower() != email.lower():
                sock.close()
                print('Emails do not match: %s != %s' % (server_email.decode(), email))
                return False
            email = bytes(self.config.email, 'utf8')
            sig = pss.new(self.config.key).sign(SHA256.new(email))
            sock.send(encryptor.encrypt(sig))
            sock.send(encryptor.encrypt(email))

            self.decryptor = decryptor
            self.encryptor = encryptor
            self.server_email = server_email
            self.server_key = server_key
            return decryptor.decrypt(sock.recv(1)) == b'\x01'
        
        except (ValueError, TypeError):
            print('Failed to decrypt message')
            print(traceback.format_exc())
        except ConnectionRefusedError:
            return False

        return False

    def ping(self, email='server@email.com', host=('127.0.0.1', 12345)):
        try:
            if self.connect(email, host, 3):
                with self.sock:
                    self.sock.send(self.encryptor.encrypt(COMMAND_PING))
                    return COMMAND_PING == self.decryptor.decrypt(self.sock.recv(1))
        except:
            pass
        return False

    def send_file(self, email, host, file):
        h = SHA256.new()
        try:
            with open(file, 'rb') as f:
                h.update(f.read())
        except FileNotFoundError:
            return False

        sig = pss.new(self.config.key).sign(h)
        try:
            if self.connect(email, host, 60):
                file_size = os.path.getsize(file)
                with self.sock as sock, open(file, 'rb') as f:
                    sock.send(self.encryptor.encrypt(COMMAND_SEND))
                    if self.decryptor.decrypt(sock.recv(1)) == b'\x01':
                        print('Contact has accepted the transfer request.')
                        sock.send(self.encryptor.encrypt(struct.pack('I', len(file))))
                        
                        sock.send(self.encryptor.encrypt(bytes(file, 'utf8')))
                        sock.send(self.encryptor.encrypt(struct.pack('Q', file_size)))
                        if self.decryptor.decrypt(sock.recv(1)) == b'\x01':
                            bytes_sent = 0
                            sock.send(self.encryptor.encrypt(sig))
                            
                            while bytes_sent < file_size:
                                chunk = f.read(1024)
                                sock.send(self.encryptor.encrypt(chunk))
                                bytes_sent += len(chunk)
                            sock.settimeout(1)
                            return self.decryptor.decrypt(sock.recv(1)) == b'\x01'
        except (struct.error, socket.timeout):
            pass
        return False


                
