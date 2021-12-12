import os
from socket import *
import crypt
from hmac import compare_digest as compare_hash
import json

from drop_protocol import SecureDropClient, SecureDropServer
from drop_config import DropConfig

def user_registration(config):
    new = input("Do you want to register a new user (y/n)? ")#option given for testing purposes only, to be removed in later version
    if new == 'y':#prompt and record the users sign up information
        name = input("Enter Full Name: ")
        email = input("Enter Email Address: ")
        password = input("Enter Password: ")
        reenter = input("Re-enter Password: ")

        if password == reenter:
            print("Passwords Match.")
            config.register(name, email, password)
            print("User Registered.")

        else:
            print("Passwords Don't Match")
    else:
        print("not adding user")

def login(config):#errors if wrong email is entered
    while True:
        #promped for login credentials
        email = input("Enter Email Address: ")

        password = input("Enter Password: ")

        if config.login(email, password):
            print("Welcome to SecureDrop.")
            break
        else:
            print("Email and Password Combination Invalid.\n\n")

def display_help():
    print(' \"add" -> Add a new contact \n')
    print(' \"list" -> List all online contacts \n')
    print(' \"send" -> Transfer file on contact \n')
    print(' \"exit" -> Exit SecureDrop')

def add_contact(config):
    contact_name = input('Enter Full Name: ')
    contact_email = input('Enter Email Address: ')
    try:
        ip = input('Enter ip: ')
        port = int(input('Enter port: '))
        config.add_contact(contact_name, contact_email, (ip, port))
        print('Contact added')
    except ValueError:
        print('Invalid port specified')
        return

def list_contacts(config, client):
    print('The following contacts are online: ')
    for contact_email in config.contacts:
        contact = config.contacts[contact_email]
        
        if client.ping(contact['email'], contact['host']):
            print('\t* %s <%s>' % (contact['name'], contact['email']))
  
def main():
    filename = input('Enter users filename(default: users.json): ')
    if len(filename) == 0:
        filename = 'users.json'
    config = DropConfig(filename)

    if len(config.get_users()) == 0:
        print("No users are registered with this client \n")
    user_registration(config)

    login(config)

    client = SecureDropClient(config)
    server = SecureDropServer(config)

    ip, port = ('127.0.0.1', 12345)
    bound = False

    while not bound:
        try:
            server.bind((ip, port))
            bound = True
        except:
            try:
                port = int(input('Failed to bind to port %d. Enter a new port: ' % port))
                if port < 23 or port > 65535:
                    raise ValueError
            except ValueError:
                print('Invalid port')

    server.start()
    print('Listening on %s:%d' % (ip, port))

    print('Type "help" for Commands.')


    while True:
        command_input = input('secure_drop> ').split(' ')
        cmd = command_input[0].lower()
        args = command_input[1:]

        if cmd.lower() == 'add':
            add_contact(config)
        elif cmd.lower() == 'list':
            list_contacts(config, client)
        elif cmd.lower() == 'send':
            if len(args) < 2:
                print('Usage: sent [email] [path]')
            else:
                email = args[0]
                filename = args[1]
                if email in client.contacts:
                    if (client.send_file(email, client.contacts[email].host, filename)):
                        print()
                else:
                    print('User not in contacts: ' + email)
        elif cmd.lower() == 'exit':
            
            server.running = False
            server.join()
            return
        elif cmd.lower() == 'help':
            display_help()
        else:
            print('Invalid command. Type "help" for Commands.')
        


if __name__ == "__main__":
    main()