from typing import *
from abc import ABC, abstractmethod

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
from Cryptodome.Util.strxor import strxor, strxor_c

class PaddingOracle(ABC):
    @abstractmethod
    def check_padding(self, data: bytes, iv: bytes) -> bool:
        pass

class PaddingOracleAttack:
    def __init__(self, oracle: PaddingOracle, verbose = False):
        self.oracle = oracle
        self.verbose = verbose
    
    def decrypt(self, data: bytes, iv: bytes) -> bytes:
        blocks = [data[i*16:(i+1)*16] for i in range(len(data) // 16)]

        decrypted_data = b''

        for i in range(len(blocks)):
            if self.verbose:
                print(f'Decrypting block #{i + 1}...')
            block_iv = iv if i == 0 else blocks[i - 1]
            decrypted_data += self._decrypt_block(blocks[i], block_iv)
        
        return unpad(decrypted_data, 16)
    
    def _decrypt_block(self, block: bytes, iv: bytes) -> bytes:
        xor = bytearray(16)
        
        for i in range(1, 17):
            for b in range(0x100):
                if self.verbose:
                    print(f'\rDecrypting byte #{17 - i:2d}, trying byte 0x{b:02x}...', end = '')
                xor[-i] = b
                if self.oracle.check_padding(block, strxor(iv, xor)):
                    # Check for false positive (... 02 02).
                    # If last byte is now actually 01, changing
                    # the second-to-last byte will not break the
                    # padding.
                    if i == 1:
                        xor[-2] = 0x01
                        if self.oracle.check_padding(block, strxor(iv, xor)):
                            break
                    else:
                        break
            
            if self.verbose:
                print(f'\rDecrypted  byte #{17 - i:2d}: 0x{b ^ i:02x}               ')
            
            if i < 16:
                strxor_c(xor, i ^ (i + 1), xor)
        
        return strxor(xor, b'\x10' * 16)
