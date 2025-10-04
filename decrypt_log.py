import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a Fernet key from a password and salt. Must be identical to the chat script."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def decrypt_log(log_file, password):
    """Reads and decrypts the chat.txt log file."""
    try:
        # The same static salt used in the chat script - FIXED typo from \cc to \xcc
        salt = b'q\x8b\xe0\xe5\x0f\xe1\x1a\x9a\xec\xbf\xf6\x8e\x9b\x0c\xcc\x1d'
        key = derive_key(password, salt)
        cipher_suite = Fernet(key)

        print(f"--- Decrypting {log_file} ---")
        with open(log_file, "rb") as f:
            for line in f:
                encrypted_message = line.strip()
                if encrypted_message:
                    try:
                        decrypted_message = cipher_suite.decrypt(encrypted_message).decode()
                        print(decrypted_message)
                    except Exception as e:
                        print(f"[Could not decrypt line... Error: {e}]")
        print("--- End of Log ---")

    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}. Check if the password is correct.")


if __name__ == "__main__":
    password_input = input("Enter the shared secret password to decrypt the log: ")
    decrypt_log("chat.txt", password_input)

