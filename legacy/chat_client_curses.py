import socket
import threading
import sys
import curses
# NEW: Import ctypes to interact with the Windows API
import ctypes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# --- Encryption ---
def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a Fernet key from a password and salt."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

class CursesTcpChatClient:
    def __init__(self, main_win, host, port, password, username):
        self.main_win = main_win
        self.host = host
        self.port = port
        self.username = username
        self.messages = []
        self.lock = threading.Lock()
        self.log_file = "chat.txt"
        self.is_running = True

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.salt = b'q\x8b\xe0\xe5\x0f\xe1\x1a\x9a\xec\xbf\xf6\x8e\x9b\x0c\xcc\x1d'
        self.key = derive_key(password, self.salt)
        self.cipher_suite = Fernet(self.key)

    def log_message(self, encrypted_message: bytes):
        with open(self.log_file, "ab") as f: f.write(encrypted_message + b'\n')
    def encrypt(self, msg: str) -> bytes: return self.cipher_suite.encrypt(msg.encode())
    def decrypt(self, msg: bytes) -> str:
        try: return self.cipher_suite.decrypt(msg).decode()
        except: return "[Decryption Error]"

    def setup_ui(self):
        curses.curs_set(1)
        self.main_win.clear()
        h, w = self.main_win.getmaxyx()
        self.msg_win = self.main_win.derwin(h - 2, w, 0, 0)
        self.msg_win.scrollok(True)
        self.input_win = self.main_win.derwin(1, w, h - 1, 0)
        self.input_win.keypad(True)
        self.main_win.hline(h - 2, 0, curses.ACS_HLINE, w)
        self.main_win.refresh()

    def redraw_messages(self):
        with self.lock:
            self.msg_win.clear()
            h, w = self.msg_win.getmaxyx()
            for msg in self.messages[-h:]: self.msg_win.addstr(f"{msg}\n")
            self.msg_win.refresh()

    def receive_messages(self):
        while self.is_running:
            try:
                encrypted_message = self.client_socket.recv(4096)
                if not encrypted_message:
                    break
                self.log_message(encrypted_message)
                message = self.decrypt(encrypted_message)
                with self.lock: self.messages.append(message)
                self.redraw_messages()
            except (ConnectionResetError, OSError, socket.error):
                break
        self.is_running = False
        with self.lock: self.messages.append("[Connection to server lost. Press Enter to exit.]")
        self.redraw_messages()

    def send_messages_loop(self):
        current_input = ""
        while self.is_running:
            self.input_win.clear()
            self.input_win.addstr(0, 0, f"Enter message: {current_input}")
            self.input_win.refresh()
            try:
                key = self.input_win.getch()
                if not self.is_running: break

                if key in (curses.KEY_ENTER, 10, 13):
                    if current_input:
                        full_message = f"{self.username} > {current_input}"
                        encrypted = self.encrypt(full_message)
                        self.log_message(encrypted)
                        self.client_socket.sendall(encrypted)
                        with self.lock: self.messages.append(full_message)
                        self.redraw_messages()
                        current_input = ""
                elif key in (curses.KEY_BACKSPACE, 8, 127): current_input = current_input[:-1]
                elif 32 <= key <= 126: current_input += chr(key)
            except (KeyboardInterrupt, SystemExit, curses.error):
                break
        self.shutdown()

    def start(self):
        try:
            self.client_socket.connect((self.host, self.port))
            self.setup_ui()
            receiver_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receiver_thread.start()
            self.send_messages_loop() # Run input loop in main thread
        except Exception as e:
            curses.endwin()
            print(f"[!] Failed to connect: {e}")

    def shutdown(self):
        self.is_running = False
        self.client_socket.close()

def main_wrapper(stdscr):
    # --- NEW: Code to disable terminal resizing on Windows ---
    original_style = None
    hwnd = None
    if sys.platform == "win32":
        try:
            # Constants for window style manipulation
            GWL_STYLE = -16
            WS_SIZEBOX = 0x00040000      # The resizing border style
            WS_MAXIMIZEBOX = 0x00010000  # The maximize button style

            # Get the handle of the console window
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                # Get the current window style
                original_style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_STYLE)
                # Remove the resizing and maximize styles
                new_style = original_style & ~WS_SIZEBOX & ~WS_MAXIMIZEBOX
                # Apply the new, non-resizable style
                ctypes.windll.user32.SetWindowLongW(hwnd, GWL_STYLE, new_style)
        except (ImportError, AttributeError):
            # Fail gracefully if ctypes is not available
            original_style = None
    
    try:
        # --- Existing code continues here ---
        height, width = stdscr.getmaxyx()
        main_win = curses.newwin(height, width, 0, 0)
        
        curses.echo()
        main_win.clear()
        main_win.addstr(0, 0, "--- Chat Client Setup ---")
        main_win.addstr(2, 0, "Enter server IP address (e.g., 127.0.0.1):")
        host = main_win.getstr(3, 0).decode('utf-8')
        main_win.addstr(5, 0, "Enter your username: ")
        username = main_win.getstr(5, 22).decode('utf-8')
        main_win.addstr(6, 0, "Enter shared secret password: ")
        password = main_win.getstr(6, 30).decode('utf-8')
        
        main_win.clear()
        main_win.addstr(0, 0, "Connecting...")
        main_win.refresh()
        
        client = CursesTcpChatClient(main_win, host, 5555, password, username)
        client.start()

    finally:
        # --- NEW: Restore the original terminal style upon exit ---
        if sys.platform == "win32" and original_style is not None and hwnd:
            # Re-apply the original style to make the window resizable again
            ctypes.windll.user32.SetWindowLongW(hwnd, GWL_STYLE, original_style)

if __name__ == "__main__":
    try:
        curses.wrapper(main_wrapper)
    except Exception as e: print(f"An error occurred: {e}")
    finally:
        try: curses.endwin()
        except: pass
        print("Chat client closed.")

