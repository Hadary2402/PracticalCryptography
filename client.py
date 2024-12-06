import socket
import threading
import hashlib
from tkinter import *
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import os

# Constants
MAX_LEN = 1024
SERVER_PORT = 8888
SERVER_IP = "127.0.0.1"
PUBLIC_KEY_FILE = "server_public_key.pem"
CHAT_HISTORY_FILE = "chathistory.txt"
CHAT_KEY_FILE = "chat_key.txt"

# Global variables
client_socket = None
server_public_key = None
session_key = None

def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def load_server_public_key():
    """Loads the server's public key."""
    global server_public_key
    if not os.path.exists(PUBLIC_KEY_FILE):
        messagebox.showerror("Error", "Server public key not found.")
        sys.exit(1)
    with open(PUBLIC_KEY_FILE, "rb") as key_file:
        server_public_key = RSA.import_key(key_file.read())

def rsa_encrypt(message):
    """Encrypt a message using the server's public key."""
    cipher = PKCS1_OAEP.new(server_public_key)
    return cipher.encrypt(message)

def aes_encrypt(data, key):
    """Encrypt data using AES."""
    cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
    return cipher.encrypt(pad(data, AES.block_size))

def aes_decrypt(data, key):
    """Decrypt data using AES."""
    cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
    return unpad(cipher.decrypt(data), AES.block_size)

def save_chat_history(message):
    """Encrypts and saves chat history to a file."""
    encrypted_message = aes_encrypt(message.encode('utf-8'), session_key)
    with open(CHAT_HISTORY_FILE, "ab") as f:
        f.write(encrypted_message + b"\n")

def send_message():
    """Sends messages to the server."""
    message = message_input.get()
    if message:
        encrypted_message = aes_encrypt(message.encode('utf-8'), session_key)
        client_socket.send(encrypted_message)
        save_chat_history(message)
        chat_area.config(state=NORMAL)
        chat_area.insert(END, f"You: {message}\n")
        chat_area.config(state=DISABLED)
        message_input.delete(0, END)

def receive_message():
    """Receives messages from the server."""
    while True:
        try:
            encrypted_message = client_socket.recv(MAX_LEN)
            message = aes_decrypt(encrypted_message, session_key).decode('utf-8')
            chat_area.config(state=NORMAL)
            chat_area.insert(END, f"{message}\n")
            chat_area.config(state=DISABLED)
            save_chat_history(message)
        except Exception as e:
            messagebox.showerror("Error", f"Connection error: {e}")
            break

def authenticate(action):
    """Handles login or signup."""
    username = username_input.get()
    password = password_input.get()
    hashed_password = hash_password(password)

    if action == "signup":
        with open("userdata.txt", "a") as f:
            f.write(f"{username} {hashed_password}\n")
        messagebox.showinfo("Success", "Signup successful!")
    elif action == "login":
        try:
            with open("userdata.txt", "r") as f:
                for line in f:
                    stored_name, stored_password = line.strip().split()
                    if stored_name == username and stored_password == hashed_password:
                        encrypted_name = aes_encrypt(username.encode('utf-8'), session_key)
                        client_socket.send(encrypted_name)
                        messagebox.showinfo("Success", f"Welcome back, {username}!")
                        chat_window()
                        return
        except FileNotFoundError:
            pass
        messagebox.showerror("Error", "Login failed. Check your username and password.")

def chat_window():
    """Opens the chat window."""
    login_window.destroy()
    global chat_area, message_input
    chat_win = Tk()
    chat_win.title("Chat Room")

    # Chat area
    chat_area = Text(chat_win, state=DISABLED, wrap=WORD)
    chat_area.pack(pady=10, padx=10, fill=BOTH, expand=True)

    # Message input
    message_frame = Frame(chat_win)
    message_frame.pack(fill=X, padx=10, pady=10)
    message_input = Entry(message_frame, width=70)
    message_input.pack(side=LEFT, fill=X, expand=True, padx=5)
    send_button = Button(message_frame, text="Send", command=send_message)
    send_button.pack(side=RIGHT)

    # Start receiving messages
    threading.Thread(target=receive_message, daemon=True).start()

    chat_win.mainloop()

def main_window():
    """Main login/signup window."""
    global login_window, username_input, password_input
    login_window = Tk()
    login_window.title("Login/Signup")

    # Username
    Label(login_window, text="Username").pack(pady=5)
    username_input = Entry(login_window)
    username_input.pack(pady=5)

    # Password
    Label(login_window, text="Password").pack(pady=5)
    password_input = Entry(login_window, show="*")
    password_input.pack(pady=5)

    # Buttons
    Button(login_window, text="Login", command=lambda: authenticate("login")).pack(side=LEFT, padx=10, pady=10)
    Button(login_window, text="Signup", command=lambda: authenticate("signup")).pack(side=RIGHT, padx=10, pady=10)

    login_window.mainloop()

def main():
    global client_socket, session_key
    load_server_public_key()

    # Generate a session key
    session_key = os.urandom(16)

    # Connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))
    encrypted_session_key = rsa_encrypt(session_key)
    client_socket.send(encrypted_session_key)

    # Save the session key for chat history encryption
    with open(CHAT_KEY_FILE, "wb") as f:
        f.write(session_key)

    main_window()

if __name__ == "__main__":
    main()
