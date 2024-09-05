Secure Password Manager
The Secure Password Manager is a Python-based tool designed to securely manage and store passwords. It uses robust encryption techniques to ensure that your sensitive information remains protected. This project provides a user-friendly interface and employs advanced cryptographic methods for secure password management.

Features
Encryption and Decryption: Utilizes Fernet symmetric encryption to securely encrypt and decrypt passwords.
Key Derivation: Employs PBKDF2 with HMAC-SHA256 to derive a secure encryption key from the master password, enhancing security.
Menu-Driven Interface: Simple text-based interface for adding, retrieving, and changing passwords.
Persistent Storage: Stores encrypted passwords in a JSON file and keeps the derived encryption key in a separate file.
File Security: Ensures sensitive data is stored securely and not directly accessible without proper decryption.
How It Works
Initialization:

On startup, the program prompts for a master password.
The master password is hashed and used to derive an encryption key.
The derived key is stored in a file (key.key) for future use.
Data Storage:

Passwords and account details are encrypted and saved in a JSON file (accounts.json).
The encryption key is stored in a separate file to maintain security.
Encryption and Decryption:

Passwords are encrypted using Fernet encryption and decrypted when retrieved.
Key Derivation:

Uses PBKDF2 with HMAC-SHA256 to derive a secure encryption key from the master password, combined with a pepper value for added security.
Interface Options:

Add Password: Save new passwords securely.
Retrieve Password: Decrypt and view stored passwords.
Change Master Password: Update the master password and regenerate the encryption key
