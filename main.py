import os
from socket import *
import crypt
from hmac import compare_digest as compare_hash
import json

from drop_server import SecureDropServer
from drop_client import SecureDropClient
from drop_config import DropConfig

class User:
    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password_hash = password

    '''
        self.toJSON()

    def toJSON(self):
        # instantiate an empty dict
        self.data = {}

        # add a team member
        self.data[self.email] = {'name': self.name, 'password': self.password_hash}
    '''

class Contact:
    def __init__(self, name, newemail, IP_addr:tuple):
        self.name = name
        #self.email = email
        self.email_hash = newemail
        self.ip_addr = IP_addr

    '''
        self.toJSON()

    def toJSON(self):
        # instantiate an empty dict
        self.data = {}

        # add a team member
        #self.data[self.name] = {'email': self.email, 'newemail':self.email_hash}
        self.data = {self.name:(self.email_hash,self.ip_addr)}
        #self.data[self.name] = {'email':self.email}
    '''


def user_registration():
    new = input("Do you want to register a new user (y/n)? ")#option given for testing purposes only, to be removed in later version
    if new == 'y':#prompt and record the users sign up information
        user = input("Enter Full Name: ")
        email = input("Enter Email Address: ")
        password = input("Enter Password: ")
        reenter = input("Re-enter Password: ")

        if password == reenter:
            print("Passwords Match.")
            writer = open('users.json', 'a')
            hash = crypt.crypt(password)#encrypt the users password before it is stored
            #wrap users credentials to be stored in json file
            new_user = User(user, email, hash)
            with open("users.json", "a") as user_file:
                json.dump(new_user.__dict__, user_file)
                user_file.close()
            print("User Registered.")

        else:
            print("Passwords Don't Match")

    if new == 'n':
        #exit
        print("not adding user")
        #exit()

def login():#errors if wrong email is entered
    login = input("Would you like to login (y/n)? ")
    if login == 'y':

        #open the file to get the users info
        f = open("users.json",)
        user_cred = json.load(f)

        while True:
            #promped for login credentials
            email_login = input("Enter Email Address: ")

            plaintext = input("Enter Password: ")

            hashed = user_cred[email_login]["password"] if email_login in user_cred else None

            if(crypt.crypt(plaintext, hashed) == hashed):
                print("Welcome to SecureDrop.")
                break
            else:
                print("Email and Password Combination Invalid.\n\n")


def addContact():
    print(' \"add" -> Add a new contact \n')
    print(' \"list" -> List all online contacts \n')
    print(' \"send" -> Transfer file on contact \n')
    print(' \"exit" -> Exit SecureDrop')
    contact = input("Please type in one of the four options: ")

    #the contact file must contain an empty python dict({}) when no contacts are present
    if contact == "add":
        newcontact = input("Enter Full Name: \n")
        newemail = input("Enter Email Address: \n")

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

        
  
def main():
    #check to see if there are no users
    users = []
    try:
        with open("users.json", "r") as f:
            users = json.loads(f.read())
    except FileNotFoundError:
        print("No users are registered with this client \n")
        user_registration()

#    login()
    addContact()

if __name__ == "__main__":
    main()


def login_test_logic():
    user_registration()

    f = open("users.json",)
    user_cred = json.load(f)

    #print(user_cred["greg@gmail.com"]["password"])
    plaintext = input("enter your password: ")
    hashed = user_cred["greg@gmail.com"]["password"]

    if not compare_hash(hashed, crypt.crypt(plaintext, hashed)):
        raise ValueError("hashed version doesn't validate against original")
        print("value error raised")

    #passed_hash = crypt.crypt(passwd)
    if(crypt.crypt(plaintext, hashed) == hashed):
        print("authentication accepted")
    else:
        print("authentication denied")
        print("  passed hash: ", crypt.crypt(plaintext, hashed), "\n", "correct hash: ", user_cred["greg@gmail.com"]["password"])
    f.close()