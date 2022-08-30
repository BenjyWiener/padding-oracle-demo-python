import socket
from typing import *

from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

class Client:
    def __init__(self, password: str, host: str, port: int):
        self.key = SHA256.new(password.encode('utf-8')).digest()
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def start(self):
        self.socket.connect((self.host, self.port))
        print(f'Connected to server on port {self.port}.')
        try:
            while True:
                msg = input('> ')
                data = self.encrypt_msg(msg)
                self.socket.sendall(data)
                resp_data = self.socket.recv(4096)
                if len(resp_data) == 0:
                    print('[SERVER DISCONNECTED]')
                    self.socket.close()
                    break
                resp_code = resp_data[:2]
                if resp_code == b'ok':
                    print('[SERVER]', self.decrypt_data(resp_data[2:]))
                elif resp_code == b'er':
                    print('[SERVER: ERROR]', resp_data[2:].decode('utf-8'))
                else:
                    print(f'[ERROR] unknown response code \'{resp_code}\'')
        except KeyboardInterrupt:
            print('Disconnecting...')
            self.socket.close()
    
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

    client = Client(password, host, port)
    client.start()
