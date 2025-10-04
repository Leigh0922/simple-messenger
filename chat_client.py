import socket
import threading
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# --- Encryption (Identical to the P2P script) ---
def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a Fernet key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

class ChatClient:
    def __init__(self, proxy_host, proxy_port, password, username):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.username = username
        self.log_file = "chat.txt"
        
        # Encryption setup
        self.salt = b'q\x8b\xe0\xe5\x0f\xe1\x1a\x9a\xec\xbf\xf6\x8e\x9b\x0c\xcc\x1d'
        self.key = derive_key(password, self.salt)
        self.cipher_suite = Fernet(self.key)

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def log_message(self, encrypted_message: bytes):
        """Logs the raw encrypted message to a file in append mode (thread-safe)."""
        with open(self.log_file, "ab") as f:
            f.write(encrypted_message + b'\n')

    def encrypt(self, message: str) -> bytes:
        """Encrypts a string message."""
        return self.cipher_suite.encrypt(message.encode())

    def decrypt(self, encrypted_message: bytes) -> str:
        """Decrypts a message and returns it as a string."""
        try:
            return self.cipher_suite.decrypt(encrypted_message).decode()
        except Exception:
            return "[Decryption Error: Bad message or wrong password]"

    def receive_messages(self):
        """Thread target to receive and display messages from the proxy."""
        while True:
            try:
                encrypted_message = self.client_socket.recv(4096)
                if not encrypted_message:
                    print("\n[!] Disconnected from proxy server.")
                    break
                
                # Log the encrypted message as soon as it's received
                self.log_message(encrypted_message)
                
                message = self.decrypt(encrypted_message)
                print(message)

            except (ConnectionResetError, OSError):
                print("\n[!] Connection to proxy lost.")
                break
        
        self.shutdown()

    def send_messages(self):
        """Main loop for user to send messages."""
        try:
            while True:
                message_text = input("")
                if message_text.lower() == 'exit':
                    break
                
                full_message = f"{self.username} > {message_text}"
                encrypted_message = self.encrypt(full_message)

                # Log the encrypted message right before sending
                self.log_message(encrypted_message)
                
                self.client_socket.sendall(encrypted_message)
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def start(self):
        """Connects to the proxy and starts the send/receive threads."""
        try:
            print(f"[*] Connecting to proxy at {self.proxy_host}:{self.proxy_port}...")
            self.client_socket.connect((self.proxy_host, self.proxy_port))
            print("[+] Connected successfully! You can start chatting.")
        except Exception as e:
            print(f"[!] Failed to connect to proxy: {e}")
            return

        # Start a thread to listen for incoming messages
        receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        receive_thread.start()
        
        # Use the main thread for sending messages
        self.send_messages()

    def shutdown(self):
        """Gracefully close the connection."""
        print("[*] Shutting down...")
        self.client_socket.close()
        sys.exit(0)


if __name__ == "__main__":
    # --- Configuration ---
    proxy_ip = input("Enter the IP address of the proxy server:\n> ")
    username = input("Enter your username:\n> ")
    password = input("Enter the shared secret password for encryption:\n> ")
    
    client = ChatClient(proxy_ip, 5555, password, username)
    client.start()