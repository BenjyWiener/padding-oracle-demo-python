import socket
from threading import Thread
from typing import *

from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

class Server:
    def __init__(self, password: str, host: str, port: int):
        self.key = SHA256.new(password.encode('utf-8')).digest()
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients: Set[Tuple[str, int]] = set()
    
    def start(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen()
        print(f'Listening on port {self.port}...')
        while True:
            (client_sock, client_addr) = self.socket.accept()
            client_thread = Thread(target=self.handle_conn, args=(client_sock, client_addr))
            self.clients.add(client_addr)
            client_thread.start()
    
    def stop(self):
        self.clients.clear()
        self.socket.close()
    
    def handle_conn(self, client_sock: socket.socket, client_addr: Tuple[str, int]):
        print(f'Connection from {client_addr[0]}:{client_addr[1]}.')
        while client_addr in self.clients:
            data = client_sock.recv(4096)
            if len(data) == 0:
                print(f'Disconnected from {client_addr[0]}:{client_addr[1]}.')
                if client_addr in self.clients:
                    self.clients.remove(client_addr)
            try:
                msg = self.decrypt_data(data)
                client_sock.sendall(b'ok' + self.encrypt_msg(msg[::-1]))
            except ValueError as e:
                client_sock.sendall(b'er' + str(e).encode('utf-8'))
        else:
            client_sock.close()
    
    def encrypt_msg(self, msg: str) -> bytes:
        cipher = AES.new(self.key, AES.MODE_CBC)
        padded_msg = pad(msg.encode('utf-8'), 16)
        return cipher.iv + cipher.encrypt(padded_msg)

    def decrypt_data(self, data: bytes) -> str:
        iv = data[:16]
        enc_data = data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_msg = cipher.decrypt(enc_data)
        return unpad(padded_msg, 16).decode('utf-8')


if __name__ == '__main__':
    import sys
    from getpass import getpass
    
    if not (3 <= len(sys.argv) <= 4) :
        print(f'Usage: {sys.argv[0]} HOST PORT [PASSWORD]')
        exit(0)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    password = sys.argv[3] if len(sys.argv) == 4 else getpass('Password: ')

    server = Server(password, host, port)
    try:
        server.start()
    except KeyboardInterrupt:
        print('Shutting down...')
        server.stop()
        exit(0)
