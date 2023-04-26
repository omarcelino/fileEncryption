import tkinter as tk
from tkinter import filedialog
from cryptography.fernet import Fernet

root = tk.Tk()
root.title("File encryption")
root.geometry("500x500")
root.resizable(False, False)

header_label = tk.Label(root, text=" HOME PAGE", font=("Arial", 20))
header_label.pack(side="top", fill="x")


def open_file_dialog():
    file_path = filedialog.askopenfilename()
    print("Selected file:", file_path)
    encrypt_file(file_path)


def encrypt_file(file_path):
    password = b"secretaryship"  # Replace with user-specified password
    key = Fernet.generate_key()
    fernet = Fernet(key)

    with open(file_path, "rb") as file:
        original_data = file.read()

    encrypted_data = fernet.encrypt(original_data)

    with open(file_path + ".encrypted", "wb") as file:
        file.write(encrypted_data)

    with open(file_path + ".key", "wb") as file:
        file.write(key)


button = tk.Button(root, text="Select File", command=open_file_dialog)
button.pack()


def decrypt_file_dialog():
    encrypted_file_path = filedialog.askopenfilename()
    print("Selected encrypted file:", encrypted_file_path)
    key_file_path = filedialog.askopenfilename()
    print("Selected key file:", key_file_path)
    decrypt_file(encrypted_file_path, key_file_path)


def decrypt_file(encrypted_file_path, key_file_path):
    with open(key_file_path, "rb") as file:
        key = file.read()
    fernet = Fernet(key)

    with open(encrypted_file_path, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = fernet.decrypt(encrypted_data)

    with open(encrypted_file_path[:-10], "wb") as file:
        file.write(decrypted_data)


decrypt_button = tk.Button(root, text="Decrypt File", command=decrypt_file_dialog)
decrypt_button.pack()

root.mainloop()
