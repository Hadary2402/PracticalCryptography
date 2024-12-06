import socket
import threading
from termcolor import colored
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import os
from colorama import init
init(autoreset=True)


# Constants
MAX_LEN = 1024
NUM_COLORS = 6
PORT = 8888
PRIVATE_KEY_FILE = "server_keys.pem"
PUBLIC_KEY_FILE = "server_public_key.pem"

# Global variables
clients = []
colors = ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan']
lock = threading.Lock()
server_key = None
session_keys = {}  # Store session keys for clients

# Terminal client structure
class TerminalClient:
    def __init__(self, client_id, name, client_socket):
        self.id = client_id
        self.name = name
        self.socket = client_socket
        self.thread = None

def color(code):
    return colors[code % NUM_COLORS]

def set_name(client_id, name):
    with lock:
        for client in clients:
            if client.id == client_id:
                client.name = name
                break

def broadcast_message(message, sender_id=None):
    with lock:
        for client in clients:
            if sender_id is None or client.id != sender_id:
                try:
                    session_key = session_keys[client.id]
                    encrypted_message = aes_encrypt(message.encode('utf-8'), session_key)
                    client.socket.send(encrypted_message)
                except Exception as e:
                    print(f"Error sending message to client {client.id}: {e}")

def end_connection(client_id):
    with lock:
        for i, client in enumerate(clients):
            if client.id == client_id:
                client.socket.close()
                clients.pop(i)
                session_keys.pop(client.id, None)
                break

def handle_client(client_socket, client_id):
    try:
        # Receive and decrypt session key
        encrypted_session_key = client_socket.recv(MAX_LEN)
        session_key = rsa_decrypt(encrypted_session_key)
        session_keys[client_id] = session_key

        # Receive client name
        encrypted_name = client_socket.recv(MAX_LEN)
        name = aes_decrypt(encrypted_name, session_key).decode('utf-8')
        set_name(client_id, name)

        welcome_message = f"{name} has joined"
        broadcast_message(welcome_message, client_id)
        print(colored(welcome_message, color(client_id)))

        while True:
            encrypted_message = client_socket.recv(MAX_LEN)
            message = aes_decrypt(encrypted_message, session_key).decode('utf-8')
            if message == "#exit":
                leave_message = f"{name} has left"
                broadcast_message(leave_message, client_id)
                print(colored(leave_message, color(client_id)))
                end_connection(client_id)
                break

            broadcast_message(f"{name}: {message}", client_id)
            print(colored(f"{name}: {message}", color(client_id)))

    except Exception as e:
        print(f"Error handling client {client_id}: {e}")
        end_connection(client_id)

def generate_or_load_keys():
    """Generate or load RSA keys."""
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        with open(PRIVATE_KEY_FILE, "rb") as private_key_file:
            private_key = RSA.import_key(private_key_file.read())
        print(colored("RSA private key loaded.", "green"))

        with open(PUBLIC_KEY_FILE, "rb") as public_key_file:
            public_key = RSA.import_key(public_key_file.read())
        print(colored("RSA public key loaded.", "green"))
    else:
        private_key = RSA.generate(2048)
        with open(PRIVATE_KEY_FILE, "wb") as private_key_file:
            private_key_file.write(private_key.export_key())
        with open(PUBLIC_KEY_FILE, "wb") as public_key_file:
            public_key_file.write(private_key.publickey().export_key())
        print(colored("RSA keys generated and saved.", "green"))
    return private_key

def rsa_encrypt(message):
    """Encrypt a message using the server's public key."""
    cipher = PKCS1_OAEP.new(server_key.publickey())
    return cipher.encrypt(message)

def rsa_decrypt(encrypted_message):
    """Decrypt a message using the server's private key."""
    cipher = PKCS1_OAEP.new(server_key)
    return cipher.decrypt(encrypted_message)

def aes_encrypt(data, key):
    """Encrypt data using AES."""
    cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
    return cipher.encrypt(pad(data, AES.block_size))

def aes_decrypt(data, key):
    """Decrypt data using AES."""
    cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
    return unpad(cipher.decrypt(data), AES.block_size)

def main():
    global server_key
    server_key = generate_or_load_keys()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', PORT))
    server_socket.listen(8)

    print(colored("\n\t  <><><>Welcome To Socket Chat Application!<><><>   ", 'cyan'))

    client_id = 0
    while True:
        try:
            client_socket, client_address = server_socket.accept()
            client_id += 1
            new_client = TerminalClient(client_id, "Anonymous", client_socket)
            with lock:
                clients.append(new_client)

            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_id))
            client_thread.start()
            new_client.thread = client_thread

        except KeyboardInterrupt:
            print("\nShutting down the server.")
            for client in clients:
                client.socket.close()
            server_socket.close()
            sys.exit(0)

if __name__ == "__main__":
    main()
