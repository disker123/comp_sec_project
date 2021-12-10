import os
from socket import *
import crypt
from hmac import compare_digest as compare_hash
import json

from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64

class DropConfig():
    def __init__(self, user_file='users.json'):
        self.user_file = user_file

        try:
            with open(user_file, 'r') as f:
                self.users = json.load(f)
        except FileNotFoundError:
            self.users = {}

    def save_users(self):
        with open(self.user_file, 'w') as f:
            json.dump(self.users, f)

    def login(self, email, password):
        #return crypt.crypt(password, self.users[email]['password'])
        if email in self.users:
            user = self.users[email]
            hashed = user['password']
            if compare_hash(crypt.crypt(password, hashed), hashed):
                self.key = RSA.import_key(base64.b64decode(user['private_key']), password)
                cipher = PKCS1_OAEP.new(self.key)
                self.contacts_key = cipher.decrypt(base64.b64decode(user['contacts_key']))

                self.contacts = {}

                for encrypted_email in user['contacts']:
                    encrypted_contact = user['contacts'][encrypted_email]
                    contact_email = self.decrypt_contact_info(encrypted_email)
                    contact = {
                        'email': contact_email,
                        'name': self.decrypt_contact_info(encrypted_contact['name']),
                        'ip': self.decrypt_contact_info(encrypted_contact['ip'])
                    }
                    
                    self.contacts[contact_email] = contact

                self.email = email
                return True
        return False

    def register(self, name, email, password):
        password_hash = crypt.crypt(password)
        self.key = RSA.generate(2048)
        self.contacts_key = get_random_bytes(32)

        cipher = PKCS1_OAEP.new(self.key)

        encrypted_key = cipher.encrypt(self.contacts_key)

        user = {
            'name': name,
            'email': email,
            'password': password_hash,
            'private_key': base64.b64encode(self.key.export_key(format='PEM', passphrase=password)).decode(),
            'contacts_key': base64.b64encode(encrypted_key).decode(),
            'contacts': {}
        }
        self.users[email] = user
        self.save_users()

    def encrypt_contact_info(self, data):
        cipher = AES.new(self.contacts_key, AES.MODE_EAX)
        nonce = cipher.nonce
        return base64.b64encode(nonce + cipher.encrypt(data))

    def decrypt_contact_info(self, data):
        data = base64.b64decode(data)
        nonce = data[:16]
        encrypted_data = data[16:]
        cipher = AES.new(self.contacts_key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt(encrypted_data)

    def add_contact(self, name, email, host):
        contact = {
            'name': name,
            'email': email,
            'host': host
        }
        self.contacts[email] = contact        

        encrypted_email = self.encrypt_contact_info(email)

        encrypted_contact = {
            'name': self.encrypt_contact_info(name),
            'email': encrypted_email,
            'ip': self.encrypt_contact_info()
        }

        self.users[email]['contacts'][encrypted_email] = encrypted_contact

        self.save_users()