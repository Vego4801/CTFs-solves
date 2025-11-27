#!/usr/bin/env python3

from pwn import *
from ctypes import CDLL

exe = ELF("./seed_spring")
context.binary = exe
libc = CDLL("libc.so.6")


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("jupiter.challenges.picoctf.org", 8311)

    return r


def main():
    r = conn()

    # Use C 'rand' and 'srand' functions so we can generate the same numbers
    now = int(time.time())
    libc.srand(now)

    for i in range(30):
        ans = str(libc.rand() & 0xF).encode('ascii')
        
        log.info(f'Sending generated answer: {ans}')
        r.sendlineafter(b'Guess the height: ', ans)

    flag = r.recvlinesS(3)[-1]
    log.warn(f'Flag obtained: {flag}')


if __name__ == "__main__":
    main()
