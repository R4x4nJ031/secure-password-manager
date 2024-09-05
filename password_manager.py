import os
import json
import base64
import bcrypt
import tkinter as tk
from tkinter import messagebox, simpledialog
from PIL import Image, ImageTk, ImageSequence
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class SecurePasswordManager:
    def __init__(self):
        self.account_type_file = 'accounts.json'
        self.key_file = 'key.key'
        self.pepper = b'my_pepper'
        self.key = self._load_or_derive_key()
        self.cipher_suite = Fernet(self.key)
        self.accounts = self._load_accounts()

    def _hash_master_password(self, master_password):
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(master_password.encode(), salt)
        return hashed_password

    def _load_or_derive_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                key_b64 = f.read()
                return base64.urlsafe_b64decode(key_b64)
        else:
            master_password = simpledialog.askstring("Master Password", "Enter your master password:")
            if not master_password:
                raise ValueError("Master password is required.")
            hashed_password = self._hash_master_password(master_password)
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(hashed_password + self.pepper)
            key_b64 = base64.urlsafe_b64encode(key)
            with open(self.key_file, 'wb') as f:
                f.write(key_b64)
            return key

    def _encrypt_password(self, password):
        encrypted_password = self.cipher_suite.encrypt(password.encode())
        return encrypted_password.decode()

    def _decrypt_password(self, encrypted_password):
        decrypted_password = self.cipher_suite.decrypt(encrypted_password.encode())
        return decrypted_password.decode()

    def _load_accounts(self):
        if os.path.exists(self.account_type_file):
            with open(self.account_type_file, 'r') as f:
                return json.load(f)
        return {}

    def _save_accounts(self):
        with open(self.account_type_file, 'w') as f:
            json.dump(self.accounts, f)

    def add_password(self, account, password):
        self.accounts[account] = self._encrypt_password(password)
        self._save_accounts()

    def get_password(self, account):
        encrypted_password = self.accounts.get(account)
        if encrypted_password:
            return self._decrypt_password(encrypted_password)
        return None

    def change_master_password(self, new_master_password):
        hashed_password = self._hash_master_password(new_master_password)
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        new_key = kdf.derive(hashed_password + self.pepper)
        new_key_b64 = base64.urlsafe_b64encode(new_key)
        with open(self.key_file, 'wb') as f:
            f.write(new_key_b64)
        self.cipher_suite = Fernet(new_key)
        self._save_accounts()

class PasswordManagerGUI:
    def __init__(self, root):
        self.manager = SecurePasswordManager()
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("500x400")
        self.root.resizable(False, False)

        # Load animations
        self.gif_image = Image.open("loading.gif")
        self.frames = [ImageTk.PhotoImage(frame) for frame in ImageSequence.Iterator(self.gif_image)]
        self.current_frame = 0

        # Create GUI elements
        self.create_widgets()

    def create_widgets(self):
        self.title_label = tk.Label(self.root, text="Secure Password Manager", font=("Helvetica", 18), bg='lightblue')
        self.title_label.pack(fill=tk.X, pady=10)

        self.add_button = tk.Button(self.root, text="Add Password", command=self.add_password, width=20)
        self.add_button.pack(pady=5)

        self.get_button = tk.Button(self.root, text="Retrieve Password", command=self.get_password, width=20)
        self.get_button.pack(pady=5)

        self.change_password_button = tk.Button(self.root, text="Change Master Password", command=self.change_master_password, width=20)
        self.change_password_button.pack(pady=5)

        self.quit_button = tk.Button(self.root, text="Exit", command=self.root.quit, width=20)
        self.quit_button.pack(pady=10)

        # Animation label
        self.anim_label = tk.Label(self.root, bg='lightblue')
        self.anim_label.pack(pady=20)
        self.animate()

    def animate(self):
        frame = self.frames[self.current_frame]
        self.current_frame = (self.current_frame + 1) % len(self.frames)
        self.anim_label.config(image=frame)
        self.root.after(100, self.animate)

    def add_password(self):
        account = simpledialog.askstring("Account", "Enter account name:")
        password = simpledialog.askstring("Password", "Enter password:")
        if account and password:
            self.manager.add_password(account, password)
            messagebox.showinfo("Success", "Password added successfully!")
        else:
            messagebox.showerror("Error", "Account and password are required.")

    def get_password(self):
        account = simpledialog.askstring("Account", "Enter account name:")
        if account:
            password = self.manager.get_password(account)
            if password:
                messagebox.showinfo("Password", f"Password for {account}: {password}")
            else:
                messagebox.showwarning("Not Found", "Account not found.")
        else:
            messagebox.showerror("Error", "Account name is required.")

    def change_master_password(self):
        new_password = simpledialog.askstring("New Master Password", "Enter new master password:")
        if new_password:
            self.manager.change_master_password(new_password)
            messagebox.showinfo("Success", "Master password changed successfully!")
        else:
            messagebox.showerror("Error", "New master password is required.")

def main():
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
