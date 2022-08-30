import socket

from padding_oracle_attack import PaddingOracle, PaddingOracleAttack

class SimOracle(PaddingOracle):
    def __init__(self, port: int = 1337):
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect(('127.0.0.1', self.port))

    def check_padding(self, data: bytes, iv: bytes) -> bool:
        self.socket.sendall(iv + data)
        resp_data = self.socket.recv(4096)
        if len(resp_data) == 0:
            return None
        resp_code = resp_data[:2]
        if resp_code == b'ok':
            return True
        elif resp_code == b'er':
            return False
        else:
            return None

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) != 3 :
        print(f'Usage: {sys.argv[0]} PORT HEXDATA')
        exit(0)
    
    port = int(sys.argv[1])
    data = bytes.fromhex(sys.argv[2])

    oracle = SimOracle(port)
    attack = PaddingOracleAttack(oracle, verbose=True)
    
    res = attack.decrypt(data[16:], data[:16])

    print('Done! Decrypted data:')
    print(res.decode('utf-8'))
