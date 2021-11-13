import os
import crypt
from hmac import compare_digest as compare_hash
import json

class User:
    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password_hash = password
        self.toJSON()

    def toJSON(self):
        # instantiate an empty dict
        self.data = {}

        # add a team member
        self.data[self.email] = {'name': self.name, 'password': self.password_hash}


class Contact:
    def __init__(self, name, email, newemail):
        self.name = name
        #self.email = email
        self.email_hash = newemail
        self.toJSON()

    def toJSON(self):
        # instantiate an empty dict
        self.data = {}

        # add a team member
        #self.data[self.name] = {'email': self.email, 'newemail':self.email_hash}
        self.data[self.name] = {'newemail':self.email_hash}
        #self.data[self.name] = {'email':self.email}



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
            new_user.toJSON()
            with open("users.json", "a") as user_file:
                json.dump(new_user.data, user_file)
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

    if contact == "add":
        newcontact = input("Enter Full Name: \n")
        newemail = input("Enter Email Address: \n")

        hash = crypt.crypt(newemail)
       
        new_contact= Contact(newcontact, newemail, hash)
        new_contact.toJSON()
        with open("contact.json", "a") as contact_file:
            json.dump(new_contact.data, contact_file)
            contact_file.close()
            
    if contact == "list":
       print("The following contacts are online: \n") 
       with open("contact.json", "r") as contact_file: 
           for key in contact_file:
               print(contact_file[key])
       #print("* " + newcontact) 
        
  
def main():
    #check to see if there are no users
    users = []
    try:
        with open("users.json", "r") as f:
            users = json.loads(f.read())
    except FileNotFoundError:
        print("No users are registered with this client \n")
        user_registration()

    login()
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
