import socket

from padding_oracle_attack import PaddingOracle, PaddingOracleAttack

class SimOracle(PaddingOracle):
    def __init__(self, host: str, port: int):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))

    def check_padding(self, data: bytes, iv: bytes) -> bool:
        self.socket.sendall(iv + data)
        resp_data = self.socket.recv(4096)
        if resp_data[:2] == b'er':
            if resp_data[2:] in [b'Padding is incorrect.', b'PKCS#7 padding is incorrect.']:
                return False
        return True

if __name__ == '__main__':
    import sys
    import time
    
    if len(sys.argv) != 4 :
        print(f'Usage: {sys.argv[0]} HOST PORT HEXDATA')
        exit(0)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    data = bytes.fromhex(sys.argv[3])

    oracle = SimOracle(host, port)
    attack = PaddingOracleAttack(oracle, verbose=True)
    
    start = time.time()

    # Skip the HMAC, use second block of
    # ciphertext as IV
    res = attack.decrypt(data[48:], data[32:48])

    end = time.time()

    print(f'Done! Decrypted data in {end - start:.3f} seconds:')
    print(res.decode('utf-8'))
