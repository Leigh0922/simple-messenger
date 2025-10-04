# Simple Messenger

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.x](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)

A secure, GUI-based client-server chat application built with Python. This project provides a straightforward platform for real-time communication, featuring a central proxy server that relays encrypted messages between multiple clients.

---

## Preview


*Caption: The server GUI (left) and two instances of the client chat window (right).*

---

## Key Features

* **Client-Server Architecture**: Utilizes a central proxy server to manage connections and relay messages between all connected clients.
* **Intuitive Graphical User Interface**: A clean and simple GUI for both the server and client, built with Python's native Tkinter library.
* **Secure Message Transmission**: Implements end-to-end encryption to ensure message privacy between users.
* **Real-time Communication**: Messages are sent and received instantly without noticeable delay.

---

## Getting Started

These instructions are for end-users who wish to run the pre-compiled application.

### Prerequisites

* A Windows operating system.

### Installation & Usage

1.  **Download the Executables**: Navigate to the `/dist` folder or click the link below to download the required files.
    * **[Download from the /dist/ folder](https://github.com/Leigh0922/simple-messenger/tree/main/dist)**
2.  **Prepare Files**: Place both `SimpleProxyGUI.exe` and `SecureChat.exe` into the same directory on your computer.
3.  **Launch the Server**: Run **`SimpleProxyGUI.exe`** to start the server. A window will appear, indicating that the server is active and awaiting connections.
4.  **Launch the Client**: Run **`SecureChat.exe`** to open the chat client. You can launch multiple instances of the client on the same machine or across different machines on the same network.
5.  **Begin Chatting**: Once connected, you can begin sending and receiving messages in real-time.

---

## For Developers

These instructions are for developers who wish to run the application from the source code.

### Prerequisites

* [Python 3](https://www.python.org/downloads/) installed on your system.
* [Git](https://git-scm.com/downloads/) installed on your system.

### Running from Source

1.  **Clone the Repository**:
    ```bash
    git clone [https://github.com/Leigh0922/simple-messenger.git](https://github.com/Leigh0922/simple-messenger.git)
    cd simple-messenger
    ```
2.  **Run the Server**: Execute the server script from the terminal.
    ```bash
    python proxy_server_v2-gui.py
    ```
3.  **Run the Client**: In a new terminal window, execute the client script.
    ```bash
    python chat_client_gui.py
    ```

---

## Technology Stack

* **Python**: Core programming language.
* **Tkinter**: Standard Python library for the graphical user interface.
* **PyInstaller**: Used to package the application into standalone executables.

---
