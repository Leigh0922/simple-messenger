import socket
import threading

class ProxyServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clients = []
        self.lock = threading.Lock()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def broadcast(self, message, sender_socket):
        """Sends a message to all clients except the sender."""
        with self.lock:
            for client in self.clients:
                if client != sender_socket:
                    try:
                        client.sendall(message)
                    except socket.error:
                        # Assume client is disconnected, remove them
                        self.remove_client(client)

    def remove_client(self, client_socket):
        """Removes a client from the list."""
        if client_socket in self.clients:
            self.clients.remove(client_socket)
            print(f"[-] Client disconnected. Total clients: {len(self.clients)}")

    def handle_client(self, client_socket, address):
        """Handles communication with a single client."""
        ip, port = address
        print(f"[+] New connection from {ip}:{port}. Total clients: {len(self.clients)}")
        
        while True:
            try:
                message = client_socket.recv(4096)
                if not message:
                    break # Client disconnected
                
                print(f"[*] Relaying message from {ip}:{port}...")
                self.broadcast(message, client_socket)

            except (ConnectionResetError, socket.error):
                break # Client forcefully closed connection
        
        with self.lock:
            self.remove_client(client_socket)
        client_socket.close()

    def start(self):
        """Starts the proxy server."""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        # The listening message is now printed in the main block

        while True:
            client_socket, address = self.server_socket.accept()
            with self.lock:
                self.clients.append(client_socket)
            
            threading.Thread(target=self.handle_client, args=(client_socket, address), daemon=True).start()


if __name__ == "__main__":
    # --- Find local IP address ---
    # This is a reliable way to get the primary LAN IP address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't have to be reachable
        s.connect(('8.8.8.8', 1))
        IP_ADDRESS = s.getsockname()[0]
    except Exception:
        # Fallback if no internet connection
        IP_ADDRESS = '127.0.0.1'
    finally:
        s.close()
    
    # --- Configuration ---
    HOST_IP = '0.0.0.0' # Listen on all interfaces
    PORT = 5555

    print("[*] Proxy server is starting...")
    print(f"[+] Your Local IP Address is: {IP_ADDRESS}")
    print("[*] Tell other users to connect to this IP.")
    
    proxy = ProxyServer(HOST_IP, PORT)
    print(f"[*] Server listening on {HOST_IP}:{PORT}")
    proxy.start()