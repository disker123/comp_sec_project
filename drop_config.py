import os
from socket import *
import crypt
from hmac import compare_digest as compare_hash
import json

from Crypto.Cipher import AES
from Crypto.Hash import SHA256

class DropConfig():
    def __init__(self, login_file='users.json', contact_file='contacts.json'):
        self.login_file = login_file
        self.contact_file = contact_file

        with open(login_file, 'r') as f:
            self.users = json.load(f)

        #TODO encrypt/decrypt contacts

        with open(contact_file, 'r') as f:
            self.encrypted_contacts = json.load(f)

    def login(self, email, password):
        return crypt.crypt(password, self.users[email]['password'])
        if email in self.users:
            hashed = self.users[email]['password']
            if compare_hash(crypt.crypt(password, hashed), hashed):
                self.key = SHA256.new(bytes(password, 'utf8') + hashed).digest()

                self.cipher = AES.new(SHA256(password).digest(), AES.MODE_EAX)

                for encrypted_contact in self.encrypted_contacts:
                    encrypted_contact

                return True
        return False

    def register(self, name, email, password):
        password_hash = crypt.crypt(password)
        user = {
            'name': name,
            'email': email,
            'password': password_hash
        }
        self.users[email] = user
        with open(self.user_file, 'w') as f:
            json.dump(self.users, f)

    def add_contact(self, name, email, ip):
        contact = {
            'name': name,
            'email': email,
            'ip': ip
        }

class User(self, name, email, password):

class Contact(self, name, newemail, IP_addr:tuple):

def addContact():
    contact = input("Please type in one of the four options: ")

    #the contact file must contain an empty python dict({}) when no contacts are present
    if contact == "add":
        hash = crypt.crypt(newemail)
        #gets your name to send to the server
        f = open("users.json",)
        user_cred = json.load(f)
        for key in user_cred:
            msg = "connection request from " + key + " "
        #sets up to communicate with server
        ip= ("127.0.0.1",12345)
        client_socket=socket(AF_INET, SOCK_DGRAM)
        client_socket.sendto(msg.encode("utf-8"),("127.0.0.1",12345))
        data, addr = client_socket.recvfrom(4096)
        print("server says")
        print(str(data))
        
        #if the server agreed to connect then add the user to your contacts
        if(data.decode('UTF-8') == 'y'):
            print('Received confirmation')
            new_contact= Contact(newemail, hash, ip)
            #make the contact and write it to the contact file
            with open("contact.json", "r+") as contact_file:
                json.dump(new_contact.__dict__, contact_file)
                contact_file.close()

        else:
            print('Verification failed')
        
        client_socket.close()

    if contact == "list":
        print("The following contacts are online: \n") 
       
        f = open("contact.json",)
        contact_file = json.load(f)
        for key in contact_file:
            client_socket=socket(AF_INET, SOCK_DGRAM)
            msg = "You up?"
            client_socket.sendto(msg.encode("utf-8"),tuple(contact_file[key][1]))
            data, addr = client_socket.recvfrom(4096)
            print(key + " is online")
        
        client_socket.close()