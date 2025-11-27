#!/usr/bin/env python3

import signal
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

TIMEOUT = 300

# assert("FLAG" in os.environ)
# flag = os.environ["FLAG"]
flag = 'BUBBABOY'
# assert(flag.startswith("CCIT{"))
# assert(flag.endswith("}"))

key = os.urandom(16)

def handle():
    while True:
        print("1. Register")
        print("2. Login")
        print("0. Exit")
        choice = int(input("> "))
        if choice == 1:
            name = input("Insert your username: ")
            if ";" in name:
                continue
            cookie = f"usr={name};is_admin=0".encode()
            iv = os.urandom(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted = cipher.encrypt(pad(cookie, 16))
            print(f"Your login token: {iv.hex()+encrypted.hex()}")
        elif choice == 2:
            token = input("Insert your token: ")
            try:
                cookie = bytes.fromhex(token[32:])
                iv = bytes.fromhex(token[:32])
                cipher = AES.new(key, AES.MODE_CBC, iv)
                pt = unpad(cipher.decrypt(cookie),16)
                values = pt.split(b";")
                user = values[0].split(b"=")[-1].decode()
                print(f"Welcome back {user} {values[1].decode()}")
                if b"is_admin=1" in values:
                    print(f"Here is your flag {flag}")
            except:
                print("Something is wrong with your token.")


if __name__ == "__main__":
    # signal.alarm(TIMEOUT)
    handle()

# First 32B are IV;     # Last block is padding if input fills correctly the block size
'IV = c21d80e291ace69e9364434880c7baaa'
'                                   ab'
'a37f25a2d524723c6ef4812016432a00-----226963ff19ef30da0bbf811d02b2c084'

# Input 'a' so the block size is exactly 16B and we can operate directly on IV
'usr=a;is_admin=1   =>  75 73 72 3d 61 3b 69 73 5f 61 64 6d 69 6e 3d 31'

# Retrieve of of D(C1, K)[last] = IV[last] XOR P1[last] (=0x30)
# Change P1[last] with D(C1, K)[] XOR IV_CHANGED[last] = 0x31
