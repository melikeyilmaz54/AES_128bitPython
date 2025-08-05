from typing import List
from functools import reduce
import numpy as np


# S-Box ve Ters S-Box dosyadan yükleniyor
sbox = np.load("Lookup Tables/s_box.npy").flatten()
inv_sbox = np.load("Lookup Tables/inv_s_box.npy").flatten()


rcon = [x.to_bytes(4, 'little') for x in [ 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, ]]

def xor_bytes(*arg: bytes) -> bytes:
    assert len({len(x) for x in arg}) == 1 # all args must have the same length
    xor_fun = lambda x, y : x ^ y
    return bytes(reduce(xor_fun, byt3s) for byt3s in zip(*arg))

def rot_word(word: bytes) -> bytes:
    '''
    apply the RotWord transformation to a bytes object of length 4
    '''
    assert len(word) == 4
    return bytes((word[(i + 1) % 4] for i in range(4)))

def inv_rot_word(word: bytes) -> bytes:
    '''
    apply the inverse of the RotWord transformation to a bytes object of length 4
    '''
    assert len(word) == 4
    return bytes((word[(i - 1) % 4] for i in range(4)))

def sub_word(word: bytes) -> bytes:
    '''
    apply the AES S-Box to each of the bytes of the 4-byte word
    '''
    assert len(word) == 4
    return bytes((sbox[w] for w in word))

def inv_sub_word(word: bytes) -> bytes:
    '''
    apply the inverse of the AES S-Box to each of the bytes of the 4-byte word
    '''
    assert len(word) == 4
    return bytes((inv_sbox[w] for w in word))


def reverse_key_schedule(round_key: bytes, aes_round: int):
    '''
    reverse the AES-128 key schedule, using a single round_key.
    '''
    assert len(round_key) * 8 == 128
    for i in range(aes_round - 1, -1, -1):
        a2 = round_key[0:4]
        b2 = round_key[4:8]
        c2 = round_key[8:12]
        d2 = round_key[12:16]

        d1 = xor_bytes(d2, c2)
        c1 = xor_bytes(c2, b2)
        b1 = xor_bytes(b2, a2)
        a1 = xor_bytes(a2, rot_word(sub_word(d1)), rcon[i])

        round_key = a1 + b1 + c1 + d1

    return round_key

def key_schedule(base_key: bytes) -> List[bytes]:
    '''
    AES-128 için key schedule işlemi. 
    16 byte (128-bit) key'den 11 adet 16-byte round key üretir.
    '''
    if len(base_key) != 16:
        raise ValueError("Only 128-bit AES keys are supported.")

    # 11 round key, her biri 4 word (4x4=16 byte) olacak
    R = 11
    W = [None for _ in range(4 * R)]

    # İlk 4 kelime: base key'den doğrudan alınır
    for i in range(4):
        W[i] = base_key[i * 4: (i + 1) * 4]

    # Kalan kelimeleri hesapla
    for i in range(4, 4 * R):
        if i % 4 == 0:
            temp = xor_bytes(W[i - 4], sub_word(rot_word(W[i - 1])), rcon[i // 4 - 1])
        else:
            temp = xor_bytes(W[i - 4], W[i - 1])
        W[i] = temp

    # 4 kelimelik blokları round key olarak birleştir
    keys = [b''.join(W[i * 4 + j] for j in range(4)) for i in range(R)]
    return keys


# from aeskeyschedule import key_schedule, reverse_key_schedule

def aes_key_input(prompt="Enter AES key (hex, 32 hex chars = 16 bytes): ") -> bytes:
    value = input(prompt).strip()
    if value.startswith("0x") or value.startswith("0X"):
        value = value[2:]

    try:
        key = bytes.fromhex(value)
    except ValueError:
        raise ValueError("Invalid hex string.")

    if len(key) != 16:
        raise ValueError("Only 128-bit AES keys are supported (16 bytes = 32 hex chars).")
    return key

def aes_round_input(prompt="Enter round number (0–10): ") -> int:
    value = int(input(prompt))
    if not (0 <= value <= 10):
        raise ValueError("Round number must be between 0 and 10.")
    return value

def main():
    print("=== AES-128 Key Schedule Viewer ===")
    round_num = aes_round_input()
    round_key = aes_key_input("Enter AES round key (or base key if round 0): ")

    # AES-128 dışındaki key'ler desteklenmiyor
    if round_num != 0:
        base_key = reverse_key_schedule(round_key, round_num)
    else:
        base_key = round_key

    keys = key_schedule(base_key)

    print("\nGenerated Round Keys:")
    for i, k in enumerate(keys):
        marker = "  <-- selected round" if i == round_num else ""
        print(f"{i:2}: {k.hex()}{marker}")

if __name__ == "__main__":
    main()
