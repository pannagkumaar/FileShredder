# FileShredder

## Overview
This Python project provides a command-line tool for securely encrypting and decrypting files using symmetric encryption. It also includes features for securely rewriting files by shredding the original data after encryption. The tool employs the Fernet symmetric encryption algorithm from the cryptography library to ensure data confidentiality.

## Functionality
### Encryption
- Encrypts a specified file using a user-provided password.
- Generates a random salt for key derivation.
- Uses PBKDF2-HMAC key derivation function for securely deriving a key from the password and salt.
- Encrypts the file content using the Fernet symmetric encryption algorithm.
- Appends the salt and encrypted data to the output file.

### Decryption
- Decrypts a previously encrypted file using the original password.
- Extracts the salt from the encrypted file to derive the decryption key.
- Decrypts the encrypted data using the derived key.

### Secure Rewriting
- Provides options to shred the original file after encryption and/or remove it.
- Shredding involves overwriting the file with random data multiple times, making it unrecoverable.
- Removing the original file ensures it's not accessible after encryption.

## Dependencies
- Python 3.x
- cryptography library

## Security Considerations
- Ensure to choose a strong password for encryption to enhance security.
- Keep the password secure and do not share it with unauthorized individuals.
- Be cautious when using the shredding and removal options, as the original data will become irrecoverable.

## Disclaimer
This tool is provided for educational purposes and should be used responsibly. The developers are not responsible for any misuse or damage caused by the tool.