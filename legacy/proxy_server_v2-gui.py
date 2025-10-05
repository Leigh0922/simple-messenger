import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

class ProxyServer:
    """The core logic of the proxy server, modified to run in a thread and log to a queue."""
    def __init__(self, host, port, log_queue):
        self.host = host
        self.port = port
        self.log_queue = log_queue
        self.clients = []
        self.lock = threading.Lock()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.is_running = False

    def log(self, message):
        """Puts a message into the queue to be displayed on the GUI."""
        self.log_queue.put(message)

    def broadcast(self, message, sender_socket):
        with self.lock:
            for client in self.clients:
                if client != sender_socket:
                    try:
                        client.sendall(message)
                    except socket.error:
                        self.remove_client(client)

    def remove_client(self, client_socket):
        if client_socket in self.clients:
            self.clients.remove(client_socket)
            self.log(f"[-] Client disconnected. Total clients: {len(self.clients)}")

    def handle_client(self, client_socket, address):
        ip, port = address
        self.log(f"[+] New connection from {ip}:{port}. Total clients: {len(self.clients)}")
        
        while self.is_running:
            try:
                message = client_socket.recv(4096)
                if not message:
                    break 
                
                self.log(f"[*] Relaying message from {ip}:{port}")
                self.broadcast(message, client_socket)
            except (socket.error, ConnectionResetError):
                break
        
        with self.lock:
            self.remove_client(client_socket)
        client_socket.close()

    def start(self):
        """Binds the server and starts the main listening loop."""
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            self.is_running = True
            self.log(f"[*] Server started. Listening on {self.get_listen_ip()}:{self.port}...")
        except Exception as e:
            self.log(f"[!] Error starting server: {e}")
            self.is_running = False
            return

        while self.is_running:
            try:
                client_socket, address = self.server_socket.accept()
                with self.lock:
                    self.clients.append(client_socket)
                
                thread = threading.Thread(target=self.handle_client, args=(client_socket, address), daemon=True)
                thread.start()
            except socket.error:
                # This will happen when we close the socket in the stop() method
                break
        
        self.log("[*] Server has stopped listening.")

    def stop(self):
        """Stops the server gracefully."""
        self.is_running = False
        # To unblock the server_socket.accept() call, we close the socket
        self.server_socket.close()
        # Recreate the socket for a potential restart
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with self.lock:
            for client in self.clients:
                client.close()
            self.clients.clear()
        self.log("[*] Server stopped and all connections closed.")
        
    def get_listen_ip(self):
        """Finds the primary local IP to display in the GUI."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't have to be reachable
            s.connect(('8.8.8.8', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1' # Fallback
        finally:
            s.close()
        return ip

class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Proxy Server Control")
        self.root.geometry("600x400")

        self.log_queue = tk.StringVar() # Using a simple variable for simplicity
        self.server = None
        self.server_thread = None

        # --- UI Elements ---
        top_frame = tk.Frame(root, padx=10, pady=10)
        top_frame.pack(fill=tk.X)

        ip_label = tk.Label(top_frame, text=f"Server IP: {self.get_listen_ip()}", font=("Helvetica", 10))
        ip_label.pack(side=tk.LEFT)
        
        port_label = tk.Label(top_frame, text="Port: 5555", font=("Helvetica", 10))
        port_label.pack(side=tk.LEFT, padx=20)

        self.status_label = tk.Label(top_frame, text="Status: Stopped", fg="red", font=("Helvetica", 10, "bold"))
        self.status_label.pack(side=tk.LEFT, expand=True)

        self.start_button = tk.Button(top_frame, text="Start Server", command=self.start_server, bg="#4CAF50", fg="white")
        self.start_button.pack(side=tk.RIGHT, padx=5)

        self.stop_button = tk.Button(top_frame, text="Stop Server", command=self.stop_server, state=tk.DISABLED, bg="#f44336", fg="white")
        self.stop_button.pack(side=tk.RIGHT)

        log_frame = tk.Frame(root, padx=10, pady=5)
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_area = scrolledtext.ScrolledText(log_frame, state=tk.DISABLED, wrap=tk.WORD, bg="#2E2E2E", fg="#D3D3D3")
        self.log_area.pack(fill=tk.BOTH, expand=True)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def log_message(self, message):
        """Thread-safe way to append a message to the log area."""
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.config(state=tk.DISABLED)
        self.log_area.yview(tk.END)

    def process_log_queue(self):
        """Checks the queue for new log messages and displays them."""
        # A simplified logger that is called directly from the server thread
        # In a more complex app, a queue is better, but this is simpler for this use case.
        pass

    def start_server(self):
        self.server = ProxyServer('0.0.0.0', 5555, self)
        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="Status: Running", fg="green")

    def stop_server(self):
        if self.server:
            self.server.stop()
            # The thread will exit on its own once the server loop is broken
            self.server = None
        
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Stopped", fg="red")
        
    def get_listen_ip(self):
        """Utility function to get local IP for display."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def on_closing(self):
        if self.server and self.server.is_running:
            if messagebox.askyesno("Exit", "Server is running. Do you want to stop it and exit?"):
                self.stop_server()
                self.root.destroy()
        else:
            self.root.destroy()

# Monkey-patch the ProxyServer to use the GUI's logging method directly
ProxyServer.log_queue = property(lambda self: self.log_queue_ref, lambda self, v: setattr(self, 'log_queue_ref', v))
def log_to_gui(self, message):
    self.log_queue_ref.log_message(message)
ProxyServer.log = log_to_gui

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerGUI(root)
    root.mainloop()
