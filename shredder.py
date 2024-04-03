import os
import argparse
import random
import string
import base64
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_random_salt():
    return os.urandom(16)

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def generate_random_key():
    return Fernet.generate_key()

def encrypt_file(file_path):
    password = getpass("Enter password for file encryption: ")
    salt = generate_random_salt()
    key = derive_key(password, salt)
    fernet = Fernet(base64.urlsafe_b64encode(key))
    
    with open(file_path, 'rb') as file:
        data = file.read()
    
    encrypted_data = fernet.encrypt(data)
    
    with open(file_path + '.encrypted', 'wb') as file:
        file.write(b'SALT' + salt + encrypted_data)

def shred_file(file_path, num_overwrites=3):
    file_size = os.path.getsize(file_path)
    with open(file_path, 'wb') as file:
        for _ in range(num_overwrites):
            random_data = os.urandom(file_size)
            file.write(random_data)

def decrypt_file(file_path):
    password = getpass("Enter password for file decryption: ")
    with open(file_path, 'rb') as file:
        data = file.read()
    
    salt = data[4:20]
    key = derive_key(password, salt)
    fernet = Fernet(base64.urlsafe_b64encode(key))
    decrypted_data = fernet.decrypt(data[20:])
    
    with open(file_path[:-10], 'wb') as file:
        file.write(decrypted_data)

def remove_file(file_path):
    os.remove(file_path)

def main():
    parser = argparse.ArgumentParser(description="Securely rewrite a file")
    parser.add_argument('file_path', type=str, help="Path to the file to be processed")
    parser.add_argument('-e', '--encrypt', action='store_true', help="Encrypt the file")
    parser.add_argument('-d', '--decrypt', action='store_true', help="Decrypt the file")
    parser.add_argument('-s', '--shred', action='store_true', help="Shred the original file after encryption")
    parser.add_argument('-r', '--remove', action='store_true', help="Remove the original file after encryption")
    args = parser.parse_args()

    if not os.path.isfile(args.file_path):
        print("Error: File not found.")
        return

    if args.encrypt:
        encrypt_file(args.file_path)
        if args.shred:
            shred_file(args.file_path)
        if args.remove:
            remove_file(args.file_path)
        print("File has been securely encrypted.")
    elif args.decrypt:
        decrypt_file(args.file_path)
        print("File has been securely decrypted.")
    elif args.shred:
        shred_file(args.file_path)
        print("File has been securely shredded.")
    else:
        print("Error: Please specify an action (-e for encryption, -d for decryption).")

if __name__ == "__main__":
    main()
