import os
import crypt
from hmac import compare_digest as compare_hash

def user_registration():
    filesize = os.path.getsize("users.txt")

    if filesize == 0:#checks to see if the system is empty and requires a user registration
        print("No users are registered with this client \n")

    new = input("Do you want to register a new user (y/n)? ")
    if new == 'y':#prompt and record the users sign up information
        user = input("Enter Full Name: ")
        email = input("Enter Email Address: ")
        password = input("Enter Password: ")
        reenter = input("Re-enter Password: ")
        
        if password == reenter:
            print("Passwords Match.")
            writer = open('users.txt', 'a')
            hash = crypt.crypt(password)#encrypt the users password before it is stored
            #if not compare_hash(hash, crypt.crypt(password, hash)):
            #    raise ValueError("hashed version doesn't validate against original")
            try:
                user_credentials = user + " " + email + " " + hash + "\n"#package all the credentials to be written to the users.txt
                writer.write(user_credentials)#writes the new user into the list
            finally:
                writer.close()
            print("User Registered.")

        else:
            print("Passwords Don't Match") 

    if new == 'n':
        #go to login program, for now print not adding user
        print("not adding user")
