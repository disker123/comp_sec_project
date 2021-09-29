print("No users are registered with this client \n")
new = input("Do you want to register a new user (y/n)? ")
if new == 'y':
    user = input("Enter Full Name: ")
    email = input("Enter Email Address: ")
    password = input("Enter Password: ")
    reenter = input("Re-enter Password: ")
  
if password == reenter:
    print("Passwords Match.")
    print("User Registered.")

else:
    print("Passwords Don't Match") 
