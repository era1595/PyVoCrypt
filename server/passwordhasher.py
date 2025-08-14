from argon2 import PasswordHasher

ph = PasswordHasher()

# Create a password for a new user
username = input("Username: ")
password = input("Password: ")

# Hash the password
hashed_password = ph.hash(password)
print(f"\nUser: {username}")
print(f"Hashed Password: {hashed_password}")
print("\nCopy this hash into the USER_DATABASE in the server code.")
