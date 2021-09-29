import os

filesize = os.path.getsize("users.txt")

if filesize == 0:
    print("No users are registered with this client \n")

new = input("Do you want to register a new user (y/n)? ")
if new == 'y':
    user = input("Enter Full Name: ")
    email = input("Enter Email Address: ")
    password = input("Enter Password: ")
    reenter = input("Re-enter Password: ")
    
    if password == reenter:
        print("Passwords Match.")
        writer = open('users.txt', 'a')
        try:
            user_credentials = user + " " + email + " " + password + "\n"
            writer.write(user_credentials)
        finally:
            writer.close()
        print("User Registered.")

    else:
        print("Passwords Don't Match") 

if new == 'n':
    #go into the program for now print not adding user
    print("not adding user")
