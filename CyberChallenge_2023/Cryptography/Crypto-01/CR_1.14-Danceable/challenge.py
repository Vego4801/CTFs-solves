#!/usr/bin/env python3

from Crypto.Cipher import ChaCha20
import os
import signal
from Crypto.Util.Padding import pad, unpad

TIMEOUT = 300

# assert("FLAG" in os.environ)
# flag = os.environ["FLAG"]
# assert(flag.startswith("CCIT{"))
# assert(flag.endswith("}"))
flag = 'BUBBABOY'

nonce = os.urandom(8)
key = os.urandom(32)


def encrypt(text):
    text = bytes.fromhex(text)
    to_encrypt = text + flag.encode()
    assert len(to_encrypt) < 256, "The message is too long!"
    padded = pad(to_encrypt, 16)
    blocks = [padded[i:i+16] for i in range(0, len(padded), 16)]
    ct = b""
    for block in blocks:
        cipher = ChaCha20.new(key=key, nonce=nonce)
        ct += cipher.encrypt(block)
    return ct.hex()


def handle():
    while True:
        print("1. Encrypt")
        print("0. Exit")
        choice = int(input("> "))
        if choice == 1:
            text = input("What do you want to encrypt (in hex)? ").strip()
            print(encrypt(text))
        else:
            break


if __name__ == "__main__":
    # signal.alarm(TIMEOUT)
    handle()
