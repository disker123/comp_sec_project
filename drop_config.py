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
        self.contacts = {}

    def save_user(self, user):
        users = self.get_users()
        users[self.hash_email(self.decrypt_contact_info(user['email']))] = user
        with open(self.user_file, 'w') as f:
            json.dump(users, f)

    def get_users(self):
        try:
            with open(self.user_file, 'r') as f:
                try:
                    return json.load(f)
                except json.decoder.JSONDecodeError:
                    pass
        except:
            pass
        return {}

    def hash_email(self, email):
        return base64.b64encode(SHA256.new(bytes(email, 'utf8').lower()).digest()).decode()

    def login(self, email, password):
        users = self.get_users()
        email_hash = self.hash_email(email)
        if email_hash in users:
            user = users[email_hash]
            hashed = user['password']
            if compare_hash(crypt.crypt(password, hashed), hashed):
                self.email = email
                self.key = RSA.import_key(base64.b64decode(user['private_key']), password)
                cipher = PKCS1_OAEP.new(self.key)
                self.contacts_key = cipher.decrypt(base64.b64decode(user['contacts_key']))

                self.contacts = {}

                for encrypted_contact in user['contacts']:
                    contact_email = self.decrypt_contact_info(encrypted_contact['email'])
                    contact = {
                        'email': contact_email,
                        'name': self.decrypt_contact_info(encrypted_contact['name']),
                        'host': (self.decrypt_contact_info(encrypted_contact['ip']), encrypted_contact['port'])
                    }
                    
                    self.contacts[contact_email.lower()] = contact

                return True

        return False

    def register(self, name, email, password):
        password_hash = crypt.crypt(password)
        self.key = RSA.generate(2048)
        self.contacts_key = get_random_bytes(32)

        cipher = PKCS1_OAEP.new(self.key)

        encrypted_key = cipher.encrypt(self.contacts_key)

        user = {
            'name': self.encrypt_contact_info(name),
            'email': self.encrypt_contact_info(email),
            'password': password_hash,
            'private_key': base64.b64encode(self.key.export_key(format='PEM', passphrase=password)).decode(),
            'contacts_key': base64.b64encode(encrypted_key).decode(),
            'contacts': []
        }
        self.save_user(user)

    def encrypt_contact_info(self, data):
        cipher = AES.new(self.contacts_key, AES.MODE_EAX)
        nonce = cipher.nonce
        return base64.b64encode(nonce + cipher.encrypt(bytes(data, 'utf8'))).decode()

    def decrypt_contact_info(self, data):
        data = base64.b64decode(data)
        nonce = data[:16]
        encrypted_data = data[16:]
        cipher = AES.new(self.contacts_key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt(encrypted_data).decode()

    def add_contact(self, name, email, host):
        contact = {
            'name': name,
            'email': email,
            'host': host,
        }
        self.contacts[email] = contact        

        encrypted_email = self.encrypt_contact_info(email)

        encrypted_contact = {
            'name': self.encrypt_contact_info(name),
            'email': encrypted_email,
            'ip': self.encrypt_contact_info(host[0]),
            'port': host[1]
        }

        users = self.get_users()
        if self.email in users:
            email_hash = self.hash_email(self.email)
            user = users[email_hash]
            encrypted_contacts = user['contacts']

            for i in range(len(encrypted_contacts)):
                if self.decrypt_contact_info(encrypted_contacts[i]['email']).lower() == email:
                    del encrypted_contacts[i]

            encrypted_contacts.append(encrypted_contact)

            self.save_user(user)