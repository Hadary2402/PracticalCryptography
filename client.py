import socket
import threading
import hashlib
import signal
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from termcolor import colored
from Crypto.Util.Padding import pad, unpad
import os
from colorama import init
init(autoreset=True)


# Constants
MAX_LEN = 1024
NUM_COLORS = 6
SERVER_PORT = 8888
SERVER_IP = "127.0.0.1"
PUBLIC_KEY_FILE = "server_public_key.pem"
CHAT_HISTORY_FILE = "chathistory.txt"
CHAT_KEY_FILE = "chat_key.txt"
exit_flag = False
colors = ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan']

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
        print("Server public key not found. Ensure the server is running and the key file is available.")
        sys.exit(1)
    with open(PUBLIC_KEY_FILE, "rb") as key_file:
        server_public_key = RSA.import_key(key_file.read())
    print("Server public key loaded successfully.")

def rsa_encrypt(message):
    """Encrypt a message using the server's public key."""
    cipher = PKCS1_OAEP.new(server_public_key)
    return cipher.encrypt(message)

def rsa_decrypt(encrypted_message):
    """Decrypt a message using the server's private key (not used here)."""
    return encrypted_message  # This is unused as we don't need to decrypt on the client side

def aes_encrypt(data, key):
    """Encrypt data using AES."""
    cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])  # IV is derived from the session key
    return cipher.encrypt(pad(data, AES.block_size))

def aes_decrypt(data, key):
    """Decrypt data using AES."""
    cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])  # IV is derived from the session key
    return unpad(cipher.decrypt(data), AES.block_size)

def write_user_data(name, hashed_password):
    """Writes user data to a file."""
    with open("userdata.txt", "a") as f:
        f.write(f"{name} {hashed_password}\n")

def read_user_data(name):
    """Reads user data from a file."""
    try:
        with open("userdata.txt", "r") as f:
            for line in f:
                stored_name, stored_password = line.strip().split()
                if stored_name == name:
                    return stored_password
    except FileNotFoundError:
        pass
    return None

def save_chat_history(message):
    """Encrypts and saves chat history to a file."""
    encrypted_message = aes_encrypt(message.encode('utf-8'), session_key)
    with open(CHAT_HISTORY_FILE, "ab") as f:
        f.write(encrypted_message + b"\n")


def save_chat_key():
    """Saves the AES key to a file."""
    with open(CHAT_KEY_FILE, "wb") as f:
        f.write(session_key)
    print("Chat encryption key saved.")

def signup():
    """Handles user signup."""
    name = input("Enter name: ").strip()
    password = input("Enter password: ").strip()
    hashed_password = hash_password(password)
    write_user_data(name, hashed_password)
    print("Signup successful!")
    return True

def login():
    """Handles user login."""
    global client_socket
    name = input("Enter your name: ").strip()
    password = input("Enter password: ").strip()
    hashed_password = hash_password(password)
    stored_password = read_user_data(name)
    if stored_password and stored_password == hashed_password:
        encrypted_name = aes_encrypt(name.encode('utf-8'), session_key)
        client_socket.send(encrypted_name)
        print(f"Login successful!\n{colored(f'Welcome back {name}!', 'cyan')}")
        return True
    print("Login failed!")
    return False

def signal_handler(signal, frame):
    """Handles Ctrl+C signal for a graceful shutdown."""
    global exit_flag
    encrypted_exit_message = aes_encrypt("#exit".encode('utf-8'), session_key)
    client_socket.send(encrypted_exit_message)
    exit_flag = True
    client_socket.close()
    sys.exit(0)

def send_message():
    """Sends messages to the server."""
    global exit_flag
    while True:
        try:
            if exit_flag:
                break
            message = input(f"{colored('You: ', 'green')}")
            encrypted_message = aes_encrypt(message.encode('utf-8'), session_key)
            client_socket.send(encrypted_message)
            
            # Save chat history
            save_chat_history(message)

            if message == "#exit":
                exit_flag = True
                break
        except Exception as e:
            print(f"Error sending message: {e}")
            break

def receive_message():
    """Receives messages from the server."""
    global exit_flag
    while True:
        try:
            if exit_flag:
                break
            encrypted_message = client_socket.recv(MAX_LEN)
            message = aes_decrypt(encrypted_message, session_key).decode('utf-8')
            print(message)
            # Save received message to history
            save_chat_history(message)
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def generate_session_key():
    """Generates a session key for AES encryption."""
    from Crypto.Random import get_random_bytes
    return get_random_bytes(16)  # AES key size is typically 16, 24, or 32 bytes

def main():
    global client_socket, session_key
    load_server_public_key()

    # Generate a session key for AES encryption
    session_key = generate_session_key()

    # Set up client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((SERVER_IP, SERVER_PORT))
        print(colored("Connected to server successfully!", "cyan"))
    except Exception as e:
        print(f"Failed to connect to server: {e}")
        sys.exit(1)

    # Send session key to the server using RSA encryption
    encrypted_session_key = rsa_encrypt(session_key)
    client_socket.send(encrypted_session_key)

    # Save the session key for chat history encryption
    save_chat_key()

    # Handle Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # Authentication
    logged_in = False
    while not logged_in:
        print("Choose an option:\n1. Sign Up\n2. Log In")
        choice = input("Your choice: ").strip()
        if choice == "1":
            signup()
        elif choice == "2":
            if login():
                logged_in = True
        else:
            print("Invalid choice!")

    # Start send and receive threads
    send_thread = threading.Thread(target=send_message)
    receive_thread = threading.Thread(target=receive_message)
    send_thread.start()
    receive_thread.start()

    send_thread.join()
    receive_thread.join()

if __name__ == "__main__":
    main()
