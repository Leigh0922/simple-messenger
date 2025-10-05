import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import queue

# --- Encryption (same as the original client) ---
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

class GuiChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat")
        self.root.geometry("500x600")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.host = ""
        self.port = 5555  # Default port
        self.username = ""
        self.password = ""

        self.client_socket = None
        self.is_running = False
        self.cipher_suite = None
        # Queue for thread-safe communication between network thread and GUI thread
        self.message_queue = queue.Queue()

        # --- Login UI ---
        self.show_login_dialog()

    def show_login_dialog(self):
        """Creates a modal dialog to get connection details from the user."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Connect to Server")
        dialog.geometry("300x200")
        dialog.transient(self.root)
        dialog.grab_set() # Make the dialog modal

        tk.Label(dialog, text="Server IP:").pack(pady=(10, 0))
        self.host_entry = tk.Entry(dialog)
        self.host_entry.pack(fill=tk.X, padx=20)
        self.host_entry.insert(0, "localhost")  # Default value for convenience

        tk.Label(dialog, text="Username:").pack(pady=(10, 0))
        self.user_entry = tk.Entry(dialog)
        self.user_entry.pack(fill=tk.X, padx=20)

        tk.Label(dialog, text="Password:").pack(pady=(10, 0))
        self.pass_entry = tk.Entry(dialog, show="*")
        self.pass_entry.pack(fill=tk.X, padx=20)

        connect_button = tk.Button(dialog, text="Connect", command=lambda: self.attempt_connection(dialog))
        connect_button.pack(pady=15)
        
        # If the user closes the login dialog, close the main app
        dialog.protocol("WM_DELETE_WINDOW", self.root.destroy)
        
        # Center the dialog
        self.root.eval(f'tk::PlaceWindow {str(dialog)} center')


    def attempt_connection(self, dialog):
        """Gets user input and tries to connect to the chat server."""
        self.host = self.host_entry.get()
        self.username = self.user_entry.get()
        self.password = self.pass_entry.get()

        if not all([self.host, self.username, self.password]):
            messagebox.showerror("Error", "All fields are required.", parent=dialog)
            return

        dialog.destroy() # Close the login dialog
        self.setup_chat_ui()
        self.start_client()

    def setup_chat_ui(self):
        """Initializes the main chat window UI components."""
        self.root.title(f"Secure Chat - {self.username}")
        
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Message display area
        self.msg_area = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, state='disabled', font=("Helvetica", 11))
        self.msg_area.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.msg_area.tag_config('user_message', foreground="#00008B") # Dark blue for own messages
        self.msg_area.tag_config('server_message', foreground="#006400") # Dark green for server
        self.msg_area.tag_config('error_message', foreground="#FF0000") # Red for errors

        # Input area
        input_frame = tk.Frame(main_frame, bg="#f0f0f0")
        input_frame.pack(fill=tk.X)

        self.input_entry = tk.Entry(input_frame, font=("Helvetica", 11))
        self.input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)
        self.input_entry.bind("<Return>", self.send_message)

        self.send_button = tk.Button(input_frame, text="Send", command=self.send_message, bg="#4CAF50", fg="white", relief="flat")
        self.send_button.pack(side=tk.RIGHT, padx=(10, 0))


    def start_client(self):
        """Initializes the client and starts communication threads."""
        try:
            # Setup encryption
            salt = b'q\x8b\xe0\xe5\x0f\xe1\x1a\x9a\xec\xbf\xf6\x8e\x9b\x0c\xcc\x1d'
            key = derive_key(self.password, salt)
            self.cipher_suite = Fernet(key)

            # Connect to server
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.host, self.port))
            self.is_running = True

            # Start thread to receive messages
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()

            # Start polling the message queue to update the UI
            self.root.after(100, self.process_message_queue)

            self.display_message("[Connected to the server]", "server_message")

        except Exception as e:
            messagebox.showerror("Connection Failed", f"Could not connect to the server: {e}")
            self.on_closing()

    def receive_messages(self):
        """Listens for incoming messages from the server in a separate thread."""
        while self.is_running:
            try:
                encrypted_message = self.client_socket.recv(4096)
                if not encrypted_message:
                    break
                # Put the received message into the queue for the main thread to process
                self.message_queue.put(encrypted_message)
            except (ConnectionResetError, OSError):
                break
        
        self.is_running = False
        # Use a special signal to indicate connection loss
        self.message_queue.put(b"__CONNECTION_LOST__")


    def process_message_queue(self):
        """Processes messages from the queue to safely update the GUI."""
        try:
            while not self.message_queue.empty():
                encrypted_message = self.message_queue.get_nowait()
                
                if encrypted_message == b"__CONNECTION_LOST__":
                    self.display_message("[Connection to server lost. Please restart the client.]", "error_message")
                    self.send_button.config(state='disabled')
                    self.input_entry.config(state='disabled')
                    continue
                
                try:
                    message = self.cipher_suite.decrypt(encrypted_message).decode()
                    self.display_message(message)
                except Exception:
                    self.display_message("[Received a corrupted message]", "error_message")

        except queue.Empty:
            pass # No messages to process
        
        # Reschedule itself to run again after 100ms
        if self.is_running:
            self.root.after(100, self.process_message_queue)

    def send_message(self, event=None):
        """Sends a message from the input entry to the server."""
        message_text = self.input_entry.get()
        if message_text and self.is_running:
            full_message = f"{self.username} > {message_text}"
            try:
                encrypted_message = self.cipher_suite.encrypt(full_message.encode())
                self.client_socket.sendall(encrypted_message)
                self.display_message(full_message, "user_message")
                self.input_entry.delete(0, tk.END)
            except Exception as e:
                self.display_message(f"[Failed to send message: {e}]", "error_message")

    def display_message(self, message, tag=None):
        """Appends a message to the text area with optional styling."""
        self.msg_area.config(state='normal')
        self.msg_area.insert(tk.END, message + "\n", tag)
        self.msg_area.config(state='disabled')
        self.msg_area.yview(tk.END) # Auto-scroll to the bottom

    def on_closing(self):
        """Handles the cleanup when the application window is closed."""
        self.is_running = False
        if self.client_socket:
            self.client_socket.close()
        self.root.destroy()

if __name__ == "__main__":
    main_root = tk.Tk()
    app = GuiChatClient(main_root)
    main_root.mainloop()
