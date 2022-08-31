import socket

from padding_oracle_attack import PaddingOracle, PaddingOracleAttack

class SimOracle(PaddingOracle):
    def __init__(self, host: str, port: int):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))

    def check_padding(self, data: bytes, iv: bytes) -> bool:
        self.socket.sendall(iv + data)
        resp_data = self.socket.recv(4096)
        if len(resp_data) == 0:
            return None
        resp_code = resp_data[:2]
        if resp_code == b'ok':
            return True
        elif resp_code == b'er':
            return resp_data[2:] not in [b'Padding is incorrect.', b'PKCS#7 padding is incorrect.']
        else:
            return None

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) != 4 :
        print(f'Usage: {sys.argv[0]} HOST PORT HEXDATA')
        exit(0)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    data = bytes.fromhex(sys.argv[3])

    oracle = SimOracle(host, port)
    attack = PaddingOracleAttack(oracle, verbose=True)
    
    res = attack.decrypt(data[16:], data[:16])

    print('Done! Decrypted data:')
    print(res[32:].decode('utf-8'))
